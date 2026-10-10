//! Bounded transport shared by the fixed caller and stdio bridge.

use std::{
    io::{Read as _, Write as _},
    net::Shutdown,
    os::unix::net::UnixStream,
    time::Duration,
};

/// The fixed service socket, never selected by tool input.
pub const SOCKET: &str = "/run/kapsel/kapseld.sock";
const RESPONSE_BYTES_MAX: usize = 40 * 1024;
const IO_DEADLINE: Duration = Duration::from_secs(2);

/// Local transport failure, never evidence of non-admission.
#[derive(Debug, Clone, Copy)]
pub enum Error {
    /// The socket could not be opened.
    Connection,
    /// The request or reply exchange did not complete.
    Exchange,
    /// The reply violated its framing bound, protocol version or status grammar.
    Response,
}

/// Exchanges one nonempty request of at most 16 KiB with the caller-supplied local socket.
///
/// The socket path belongs to application composition, not tool input. The response is bounded to
/// 40 KiB before allocation. This function checks framing and the JSON version/status envelope.
/// It returns the original response bytes and recognized version-1 status token.
/// The caller must validate command-specific fields. Envelope acceptance does not establish an
/// operation result, and a failure never establishes non-admission.
///
/// # Errors
///
/// Returns a bounded local transport error for invalid request size, connection, exchange or
/// framing or envelope failure.
pub fn exchange(socket: &str, request: &[u8]) -> Result<(Vec<u8>, String), Error> {
    if request.is_empty() || request.len() > 16 * 1024 {
        return Err(Error::Exchange);
    }

    let mut stream = UnixStream::connect(socket).map_err(|_| Error::Connection)?;
    stream
        .set_read_timeout(Some(IO_DEADLINE))
        .map_err(|_| Error::Exchange)?;
    stream
        .set_write_timeout(Some(IO_DEADLINE))
        .map_err(|_| Error::Exchange)?;
    let request_length = u32::try_from(request.len()).map_err(|_| Error::Exchange)?;
    stream
        .write_all(&request_length.to_be_bytes())
        .map_err(|_| Error::Exchange)?;
    stream.write_all(request).map_err(|_| Error::Exchange)?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|_| Error::Exchange)?;

    let mut prefix = [0_u8; 4];
    stream
        .read_exact(&mut prefix)
        .map_err(|_| Error::Exchange)?;
    let response_length =
        usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| Error::Response)?;
    if response_length == 0 || response_length > RESPONSE_BYTES_MAX {
        return Err(Error::Response);
    }
    let mut response = vec![0_u8; response_length];
    stream
        .read_exact(&mut response)
        .map_err(|_| Error::Exchange)?;
    let mut trailing = [0_u8; 1];
    if stream.read(&mut trailing).map_err(|_| Error::Exchange)? != 0 {
        return Err(Error::Response);
    }

    let status = validate_response_envelope(&response)?;
    Ok((response, status))
}

/// Checks a bounded JSON response header and returns its recognized version-1 status token.
///
/// This check does not validate command-specific fields or establish an operation result.
/// The caller must validate the payload for its selected command.
///
/// # Errors
///
/// Returns [`Error::Response`] for oversized or malformed JSON, a non-object response,
/// an unsupported version or an unrecognized status token.
fn validate_response_envelope(bytes: &[u8]) -> Result<String, Error> {
    #[derive(serde::Deserialize)]
    struct Header {
        version: u8,
        status: String,
    }
    if bytes.is_empty()
        || bytes.len() > RESPONSE_BYTES_MAX
        || bytes.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{')
    {
        return Err(Error::Response);
    }
    let header: Header = serde_json::from_slice(bytes).map_err(|_| Error::Response)?;
    if header.version != 1
        || !matches!(
            header.status.as_str(),
            "READY"
                | "NOT_FOUND"
                | "NOT_READY"
                | "IN_PROGRESS"
                | "NOT_ATTEMPTED"
                | "SUCCEEDED"
                | "FAILED"
                | "UNKNOWN"
                | "ADMITTED"
                | "NOT_ADMITTED"
                | "INDETERMINATE"
                | "ERROR"
        )
    {
        return Err(Error::Response);
    }
    Ok(header.status)
}

#[cfg(test)]
mod tests {
    //! Socket-boundary checks for framing, envelope acceptance and local failure classes.

    use std::{
        fs,
        io::{Read as _, Write as _},
        os::unix::net::UnixListener,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
        thread,
    };

    use super::{exchange, Error, IO_DEADLINE, RESPONSE_BYTES_MAX};

    const REQUEST: &[u8] =
        br#"{"version":1,"request":"submit_set_deployment_image","operation_id":"a"}"#;

    struct FixtureDirectory(PathBuf);

    impl FixtureDirectory {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "kt-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for FixtureDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn frame(bytes: &[u8]) -> Vec<u8> {
        let mut frame = u32::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
        frame.extend_from_slice(bytes);
        frame
    }

    fn exchange_reply(reply: Vec<u8>) -> Result<(Vec<u8>, String), Error> {
        let directory = FixtureDirectory::new();
        let socket = directory.0.join("s");
        let listener = UnixListener::bind(&socket).unwrap();
        let peer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(IO_DEADLINE)).unwrap();
            stream.set_write_timeout(Some(IO_DEADLINE)).unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            assert_eq!(request, frame(REQUEST));
            // Rejected prefixes can close the client before the peer finishes writing.
            let _ = stream.write_all(&reply);
        });

        let result = exchange(socket.to_str().unwrap(), REQUEST);

        peer.join().unwrap();
        result
    }

    #[test]
    fn exchange_preserves_bytes_and_recognizes_every_existing_status() {
        for status in [
            "READY",
            "NOT_FOUND",
            "NOT_READY",
            "IN_PROGRESS",
            "NOT_ATTEMPTED",
            "SUCCEEDED",
            "FAILED",
            "UNKNOWN",
            "ADMITTED",
            "NOT_ADMITTED",
            "INDETERMINATE",
            "ERROR",
        ] {
            let bytes = format!(" {{\"status\":\"{status}\", \"version\":1}}\n").into_bytes();
            let (original, recognized) = exchange_reply(frame(&bytes)).unwrap();

            assert_eq!(original, bytes);
            assert_eq!(recognized, status);
        }
    }

    #[test]
    fn exchange_rejects_invalid_envelopes_without_a_caller_validation_step() {
        for invalid in [
            r#"{"status":"ADMITTED"}"#,
            r#"{"version":2,"status":"ADMITTED"}"#,
            r#"{"version":1.0,"status":"ADMITTED"}"#,
            r#"{"version":"1","status":"ADMITTED"}"#,
            r#"{"version":1,"version":1,"status":"ADMITTED"}"#,
            r#"{"version":1,"\u0076ersion":1,"status":"ADMITTED"}"#,
            r#"{"version":1,"status":"ADMITTED","status":"UNKNOWN"}"#,
            r#"{"version":1,"status":"ADMITTED","\u0073tatus":"ADMITTED"}"#,
            r#"{"version":1}"#,
            r#"{"version":1,"status":null}"#,
            r#"[1,"ADMITTED"]"#,
            r#"{"version":1,"status":"ACCEPTED"}"#,
            r#"{"version":1,"status":"ADMITTED"}{}"#,
            "not JSON",
        ] {
            assert!(matches!(
                exchange_reply(frame(invalid.as_bytes())),
                Err(Error::Response)
            ));
        }
        assert!(matches!(
            exchange_reply(frame(&[0xff])),
            Err(Error::Response)
        ));
    }

    #[test]
    fn envelope_acceptance_leaves_command_payload_checks_with_the_caller() {
        let bytes = br#"{"version":1,"status":"READY","receipt_hex":false}"#;
        let (original, status) = exchange_reply(frame(bytes)).unwrap();
        assert_eq!(original, bytes);
        assert_eq!(status, "READY");
    }

    #[test]
    fn response_bounds_and_trailing_bytes_remain_response_errors() {
        for length in [0, RESPONSE_BYTES_MAX + 1] {
            let prefix = u32::try_from(length).unwrap().to_be_bytes().to_vec();
            assert!(matches!(exchange_reply(prefix), Err(Error::Response)));
        }
        let mut maximum = br#"{"version":1,"status":"UNKNOWN"}"#.to_vec();
        maximum.resize(RESPONSE_BYTES_MAX, b' ');
        assert_eq!(exchange_reply(frame(&maximum)).unwrap().0, maximum);

        let mut trailing = frame(br#"{"version":1,"status":"ADMITTED"}"#);
        trailing.push(b' ');
        assert!(matches!(exchange_reply(trailing), Err(Error::Response)));
    }

    #[test]
    fn incomplete_replies_remain_exchange_errors_not_admission_refusals() {
        for reply in [vec![], vec![0, 0], vec![0, 0, 0, 2, b'{']] {
            assert!(matches!(exchange_reply(reply), Err(Error::Exchange)));
        }
    }

    #[test]
    fn request_bounds_are_checked_before_connection() {
        let directory = FixtureDirectory::new();
        let missing = directory.0.join("absent");
        let socket = missing.to_str().unwrap();
        assert!(matches!(exchange(socket, &[]), Err(Error::Exchange)));
        assert!(matches!(
            exchange(socket, &vec![b' '; 16 * 1024 + 1]),
            Err(Error::Exchange)
        ));
        assert!(matches!(exchange(socket, REQUEST), Err(Error::Connection)));
    }
}
