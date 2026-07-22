//! Bounded HTTP/1.1 transport for the fixed native sandbox service.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri};
use kapsel_sandbox::Service;

const REQUEST_HEAD_MAX: usize = 8 * 1024;
const REQUEST_LINE_MAX: usize = 512;
const HEADER_COUNT_MAX: usize = 16;
const HEADER_VALUE_MAX: usize = 256;
const REQUEST_BODY_MAX: usize = 512;
const CONNECTIONS_MAX: usize = 128;
const IN_FLIGHT_MAX: usize = 64;
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(5);
const HANDLE_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) fn serve(service: Service, address: SocketAddr) -> Result<(), &'static str> {
    let listener = TcpListener::bind(address).map_err(|_| "listener bind failed")?;
    let bound = listener
        .local_addr()
        .map_err(|_| "listener address failed")?;
    println!("LISTEN_ADDR={bound}");
    let service = Arc::new(service);
    let connections = Arc::new(AtomicUsize::new(0));
    let in_flight = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let Ok(stream) = incoming else {
            continue;
        };
        if !try_acquire(&connections, CONNECTIONS_MAX) {
            drop(stream);
            continue;
        }
        let service = Arc::clone(&service);
        let connections = Arc::clone(&connections);
        let in_flight = Arc::clone(&in_flight);
        thread::spawn(move || {
            handle_connection(stream, service, in_flight);
            connections.fetch_sub(1, Ordering::AcqRel);
        });
    }
    Err("listener stopped")
}

fn handle_connection(mut stream: TcpStream, service: Arc<Service>, in_flight: Arc<AtomicUsize>) {
    if stream.set_write_timeout(Some(RECEIVE_TIMEOUT)).is_err() {
        return;
    }
    let request = match read_request(&mut stream) {
        Ok(request) => request,
        Err(ParseFailure::BoundedResponse) => {
            let _ = write_response(&mut stream, plain_error(StatusCode::BAD_REQUEST));
            return;
        },
        Err(ParseFailure::Close) => return,
    };
    if !try_acquire(&in_flight, IN_FLIGHT_MAX) {
        return;
    }
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    thread::spawn(move || {
        let response = service.handle_http(&request, unix_time().unwrap_or(0));
        in_flight.fetch_sub(1, Ordering::AcqRel);
        let _ = sender.send(response);
    });
    if let Ok(response) = receiver.recv_timeout(HANDLE_TIMEOUT) {
        let _ = write_response(&mut stream, response);
    }
}

fn read_request(stream: &mut TcpStream) -> Result<Request<Vec<u8>>, ParseFailure> {
    let mut bytes = Vec::with_capacity(1024);
    let header_deadline = std::time::Instant::now() + RECEIVE_TIMEOUT;
    let head_end = loop {
        if bytes.len() >= REQUEST_HEAD_MAX {
            return Err(ParseFailure::Close);
        }
        set_remaining_timeout(stream, header_deadline)?;
        let mut chunk = [0_u8; 512];
        let remaining_capacity = REQUEST_HEAD_MAX - bytes.len();
        let read_max = remaining_capacity.min(chunk.len());
        let read = stream
            .read(&mut chunk[..read_max])
            .map_err(|_| ParseFailure::Close)?;
        if read == 0 {
            return Err(ParseFailure::Close);
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(end) = find_head_end(&bytes) {
            if end > REQUEST_HEAD_MAX {
                return Err(ParseFailure::Close);
            }
            break end;
        }
    };
    let request_line_end = bytes
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or(ParseFailure::Close)?;
    if request_line_end > REQUEST_LINE_MAX {
        return Err(ParseFailure::Close);
    }

    let mut parsed_headers = [httparse::EMPTY_HEADER; HEADER_COUNT_MAX];
    let mut parsed = httparse::Request::new(&mut parsed_headers);
    let Ok(httparse::Status::Complete(parsed_end)) = parsed.parse(&bytes[..head_end]) else {
        return Err(ParseFailure::Close);
    };
    if parsed_end != head_end || parsed.version != Some(1) {
        return Err(ParseFailure::Close);
    }
    let method = parsed.method.ok_or(ParseFailure::Close)?;
    let path = parsed.path.ok_or(ParseFailure::Close)?;
    let mut builder = Request::builder()
        .method(Method::from_bytes(method.as_bytes()).map_err(|_| ParseFailure::Close)?)
        .uri(path.parse::<Uri>().map_err(|_| ParseFailure::Close)?);
    let headers = builder.headers_mut().ok_or(ParseFailure::Close)?;
    for header in &*parsed.headers {
        if header.value.len() > HEADER_VALUE_MAX {
            return Err(ParseFailure::Close);
        }
        let name =
            HeaderName::from_bytes(header.name.as_bytes()).map_err(|_| ParseFailure::Close)?;
        let value = HeaderValue::from_bytes(header.value).map_err(|_| ParseFailure::Close)?;
        headers.append(name, value);
    }

    let content_length = content_length(parsed.headers)?;
    if content_length > REQUEST_BODY_MAX {
        return Err(ParseFailure::BoundedResponse);
    }
    let buffered_body = bytes
        .len()
        .checked_sub(head_end)
        .ok_or(ParseFailure::Close)?;
    if buffered_body > content_length {
        return Err(ParseFailure::Close);
    }
    let mut body = bytes.split_off(head_end);
    let body_deadline = std::time::Instant::now() + RECEIVE_TIMEOUT;
    while body.len() < content_length {
        set_remaining_timeout(stream, body_deadline)?;
        let remaining = content_length - body.len();
        let mut chunk = [0_u8; REQUEST_BODY_MAX];
        let read = stream
            .read(&mut chunk[..remaining])
            .map_err(|_| ParseFailure::Close)?;
        if read == 0 {
            return Err(ParseFailure::Close);
        }
        body.extend_from_slice(&chunk[..read]);
    }
    builder.body(body).map_err(|_| ParseFailure::Close)
}

fn set_remaining_timeout(
    stream: &TcpStream,
    deadline: std::time::Instant,
) -> Result<(), ParseFailure> {
    let remaining = deadline
        .checked_duration_since(std::time::Instant::now())
        .ok_or(ParseFailure::Close)?;
    if remaining.is_zero() || stream.set_read_timeout(Some(remaining)).is_err() {
        return Err(ParseFailure::Close);
    }
    Ok(())
}

fn content_length(headers: &[httparse::Header<'_>]) -> Result<usize, ParseFailure> {
    let mut length = None;
    for header in headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(ParseFailure::Close);
            }
            let text = std::str::from_utf8(header.value).map_err(|_| ParseFailure::Close)?;
            if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(ParseFailure::Close);
            }
            length = Some(text.parse().map_err(|_| ParseFailure::Close)?);
        }
    }
    Ok(length.unwrap_or(0))
}

fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn try_acquire(counter: &AtomicUsize, maximum: usize) -> bool {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current < maximum).then_some(current + 1)
        })
        .is_ok()
}

fn plain_error(status: StatusCode) -> Response<Vec<u8>> {
    let mut response = Response::new(Vec::new());
    *response.status_mut() = status;
    response
}

fn write_response(stream: &mut TcpStream, response: Response<Vec<u8>>) -> std::io::Result<()> {
    let (parts, body) = response.into_parts();
    write!(
        stream,
        "HTTP/1.1 {} {}\r\n",
        parts.status.as_u16(),
        parts.status.canonical_reason().unwrap_or("Response")
    )?;
    let has_content_length = parts.headers.contains_key(http::header::CONTENT_LENGTH);
    for (name, value) in &parts.headers {
        stream.write_all(name.as_str().as_bytes())?;
        stream.write_all(b": ")?;
        stream.write_all(value.as_bytes())?;
        stream.write_all(b"\r\n")?;
    }
    if !has_content_length {
        write!(stream, "content-length: {}\r\n", body.len())?;
    }
    stream.write_all(b"connection: close\r\n\r\n")?;
    stream.write_all(&body)?;
    stream.flush()
}

fn unix_time() -> Result<i64, ()> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_secs();
    i64::try_from(seconds).map_err(|_| ())
}

#[derive(Clone, Copy)]
enum ParseFailure {
    BoundedResponse,
    Close,
}

#[cfg(test)]
mod tests {
    use super::{content_length, find_head_end, try_acquire};
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn raw_bounds_helpers_fail_closed() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\nrest"), Some(18));
        let duplicate = [
            httparse::Header {
                name: "content-length",
                value: b"1",
            },
            httparse::Header {
                name: "Content-Length",
                value: b"1",
            },
        ];
        assert!(content_length(&duplicate).is_err());
        let counter = AtomicUsize::new(0);
        assert!(try_acquire(&counter, 1));
        assert!(!try_acquire(&counter, 1));
    }
}
