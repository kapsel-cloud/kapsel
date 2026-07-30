//! Fixed private runner-to-system handoff for the sandbox.
//!
//! This is one concrete deployment adapter. It is not a public protocol, queue, provider seam, or
//! compatibility promise.

use std::{
    fmt,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use kapsel::{
    AgentRequest, Application, OperationReport, OperationResult, OperationState, TargetRejection,
};
use sha2::{Digest, Sha256};

use crate::Service;

pub(crate) const BODY_BYTES_MAX: usize = 20 * 1024;
pub(crate) const RECEIPT_BYTES_MAX: usize = 16 * 1024;
const OPEN_CONNECTIONS_MAX: usize = 16;
const HANDLERS_MAX: usize = 8;
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const INVOKED_MAGIC: &[u8] = b"KAPSEL-SANDBOX-APPLICATION-INVOKED-V1\0";
const REPORT_MAGIC: &[u8] = b"KAPSEL-SANDBOX-APPLICATION-REPORT-V1\0";
const INVOKED_ACK_MAGIC: &[u8] = b"KAPSEL-SANDBOX-APPLICATION-INVOKED-ACK-V1\0";
const REPORT_ACK_MAGIC: &[u8] = b"KAPSEL-SANDBOX-APPLICATION-REPORT-ACK-V1\0";
const REJECTED_MAGIC: &[u8] = b"KAPSEL-SANDBOX-HANDOFF-REJECTED-V1\0";
const COMMITTED: &[u8] = b"committed";
const VERIFIER_DOMAIN: &[u8] = b"KAPSEL-SANDBOX-HANDOFF-CREDENTIAL-V1\0";
const REPORT_DOMAIN: &[u8] = b"KAPSEL-SANDBOX-HANDOFF-REPORT-V1\0";

/// Current private runner assignment. Its secret-bearing fields are intentionally not `Debug`.
pub struct HandoffAssignment {
    /// Public run identity bound to the private assignment.
    pub(crate) run_id: String,
    /// KAP-0038 operation identity bound to the run.
    pub(crate) operation_id: String,
    /// Current revocable scheduler lease identity.
    pub(crate) lease_id: String,
    /// Raw per-lease credential delivered only through the owner-private channel.
    pub(crate) credential: [u8; 32],
    /// Configured owner-private system endpoint.
    pub(crate) endpoint: SocketAddr,
}

/// Exact terminal report accepted by the system side.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TerminalHandoffReport {
    /// One KAP-0038 pre-attempt target rejection and no receipt.
    NotAttempted(TargetRejection),
    /// One receiver result plus exact frozen receipt bytes.
    Finalized {
        /// Unchanged KAP-0038 receiver result.
        result: OperationResult,
        /// Lowercase SHA-256 digest of the exact bytes.
        receipt_digest: String,
        /// Exact frozen receipt bytes, never a path.
        receipt_bytes: Vec<u8>,
    },
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct HandoffIdentity {
    pub(crate) run_id: String,
    pub(crate) operation_id: String,
    pub(crate) lease_id: String,
    pub(crate) credential: [u8; 32],
}

impl fmt::Debug for HandoffIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandoffIdentity")
            .field("run_id", &self.run_id)
            .field("operation_id", &self.operation_id)
            .field("lease_id", &self.lease_id)
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Request {
    Invoked(HandoffIdentity),
    Report(HandoffIdentity, TerminalHandoffReport),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AckKind {
    Invoked,
    Report,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Response {
    Committed(AckKind, HandoffIdentity),
    Rejected,
}

/// Runs one application behind the authenticated private handoff.
///
/// The durable invocation acknowledgement precedes the first lifecycle call. Reconciliation always
/// runs first; execution is permitted only when it proves that no gateway operation exists.
///
/// # Errors
///
/// Returns a fixed handoff, application, receipt, or I/O failure without reflecting private input.
pub async fn run_application_handoff(
    mut application: Application,
    request: &AgentRequest,
    assignment: &HandoffAssignment,
) -> Result<OperationReport, HandoffError> {
    if request.operation_id != assignment.operation_id
        || !application.request_matches_authorized_grant(request)
    {
        return Err(HandoffError::Rejected);
    }
    let identity = assignment.identity();
    send_request(
        assignment.endpoint,
        &Request::Invoked(identity.clone()),
        AckKind::Invoked,
    )?;
    let report = match application
        .reconcile()
        .await
        .map_err(|_| HandoffError::Application)?
    {
        Some(report) => report,
        None => application
            .execute(request)
            .await
            .map_err(|_| HandoffError::Application)?,
    };
    let terminal = terminal_report(&report)?;
    send_request(
        assignment.endpoint,
        &Request::Report(identity, terminal),
        AckKind::Report,
    )?;
    Ok(report)
}

/// Fixed private handoff failure vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffError {
    /// Authentication, identity, grammar, or acknowledgement was rejected.
    Rejected,
    /// The private endpoint was unavailable or violated a bound.
    Unavailable,
    /// The configured application could not open or advance.
    Application,
}

impl HandoffAssignment {
    /// Returns the current private lease identity for owner-controlled runner delivery.
    #[must_use]
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    /// Returns the raw per-lease credential for one owner-private runner delivery.
    ///
    /// The caller must not persist it in system state or include it in diagnostics.
    #[must_use]
    pub fn credential(&self) -> [u8; 32] {
        self.credential
    }

    /// Returns the configured private endpoint for owner-controlled runner delivery.
    #[must_use]
    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub(crate) fn identity(&self) -> HandoffIdentity {
        HandoffIdentity {
            run_id: self.run_id.clone(),
            operation_id: self.operation_id.clone(),
            lease_id: self.lease_id.clone(),
            credential: self.credential,
        }
    }
}

pub(crate) fn credential_verifier(identity: &HandoffIdentity) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(VERIFIER_DOMAIN);
    digest.update(identity.run_id.as_bytes());
    digest.update(identity.operation_id.as_bytes());
    digest.update(identity.lease_id.as_bytes());
    digest.update(identity.credential);
    digest.finalize().into()
}

pub(crate) fn report_payload_digest(
    run_id: &str,
    operation_id: &str,
    report: &TerminalHandoffReport,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(REPORT_DOMAIN);
    digest.update(run_id.as_bytes());
    digest.update(operation_id.as_bytes());
    match report {
        TerminalHandoffReport::NotAttempted(rejection) => {
            digest.update(b"not_attempted\0");
            digest.update(rejection_token(*rejection).as_bytes());
        },
        TerminalHandoffReport::Finalized {
            result,
            receipt_digest,
            receipt_bytes,
        } => {
            digest.update(b"finalized\0");
            digest.update(result_token(*result).as_bytes());
            digest.update(receipt_digest.as_bytes());
            digest.update(receipt_bytes);
        },
    }
    digest.finalize().into()
}

pub(crate) fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

/// Serves the fixed private system endpoint until the listener closes.
///
/// # Errors
///
/// Returns only a bounded private transport failure.
pub fn serve_private_handoff(
    listener: &TcpListener,
    service: &Arc<Service>,
) -> Result<(), HandoffError> {
    let open = Arc::new(AtomicUsize::new(0));
    let handlers = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let stream = incoming.map_err(|_| HandoffError::Unavailable)?;
        if open.fetch_add(1, Ordering::AcqRel) >= OPEN_CONNECTIONS_MAX {
            open.fetch_sub(1, Ordering::AcqRel);
            continue;
        }
        if handlers.fetch_add(1, Ordering::AcqRel) >= HANDLERS_MAX {
            handlers.fetch_sub(1, Ordering::AcqRel);
            open.fetch_sub(1, Ordering::AcqRel);
            continue;
        }
        let service = Arc::clone(service);
        let open = Arc::clone(&open);
        let handlers = Arc::clone(&handlers);
        std::thread::spawn(move || {
            let _ = handle_connection(stream, &service);
            handlers.fetch_sub(1, Ordering::AcqRel);
            open.fetch_sub(1, Ordering::AcqRel);
        });
    }
    Ok(())
}

pub(crate) fn handle_connection(stream: TcpStream, service: &Service) -> Result<(), HandoffError> {
    handle_connection_with_time(stream, service, None, RECEIVE_TIMEOUT)
}

pub(crate) fn handle_connection_at(
    stream: TcpStream,
    service: &Service,
    now: i64,
) -> Result<(), HandoffError> {
    handle_connection_with_time(stream, service, Some(now), RECEIVE_TIMEOUT)
}

fn handle_connection_with_time(
    mut stream: TcpStream,
    service: &Service,
    fixed_now: Option<i64>,
    receive_timeout: Duration,
) -> Result<(), HandoffError> {
    stream
        .set_write_timeout(Some(RESPONSE_TIMEOUT))
        .map_err(|_| HandoffError::Unavailable)?;
    let receive_deadline = Instant::now()
        .checked_add(receive_timeout)
        .ok_or(HandoffError::Unavailable)?;
    let body = read_frame_until(&mut stream, receive_deadline)?;
    let Ok(request) = decode_request(&body) else {
        write_frame(&mut stream, &encode_response(&Response::Rejected))?;
        return Ok(());
    };
    let system = service.clone();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let commit_now = fixed_now.map_or_else(unix_time, Ok);
        let response = match (request, commit_now) {
            (Request::Invoked(identity), Ok(now)) => {
                match system.commit_application_invoked(&identity, now) {
                    Ok(()) => Response::Committed(AckKind::Invoked, identity),
                    Err(_) => Response::Rejected,
                }
            },
            (Request::Report(identity, report), Ok(now)) => {
                match system.commit_application_report(&identity, &report, now) {
                    Ok(()) => Response::Committed(AckKind::Report, identity),
                    Err(_) => Response::Rejected,
                }
            },
            (Request::Invoked(_) | Request::Report(_, _), Err(_)) => Response::Rejected,
        };
        let _ = sender.send(response);
    });
    let response = receiver
        .recv_timeout(RESPONSE_TIMEOUT)
        .map_err(|_| HandoffError::Unavailable)?;
    write_frame(&mut stream, &encode_response(&response))
}

fn terminal_report(report: &OperationReport) -> Result<TerminalHandoffReport, HandoffError> {
    match report.state {
        OperationState::NotAttempted => report
            .target_rejection
            .map(TerminalHandoffReport::NotAttempted)
            .ok_or(HandoffError::Application),
        OperationState::Finalized => {
            let result = report.result.ok_or(HandoffError::Application)?;
            let receipt = report.receipt.as_ref().ok_or(HandoffError::Application)?;
            let bytes = std::fs::read(&receipt.path).map_err(|_| HandoffError::Unavailable)?;
            if bytes.is_empty()
                || bytes.len() > RECEIPT_BYTES_MAX
                || lowercase_hex(&Sha256::digest(&bytes)) != receipt.digest
            {
                return Err(HandoffError::Unavailable);
            }
            Ok(TerminalHandoffReport::Finalized {
                result,
                receipt_digest: receipt.digest.clone(),
                receipt_bytes: bytes,
            })
        },
        _ => Err(HandoffError::Application),
    }
}

fn send_request(
    endpoint: SocketAddr,
    request: &Request,
    expected: AckKind,
) -> Result<(), HandoffError> {
    let mut stream = TcpStream::connect_timeout(&endpoint, RECEIVE_TIMEOUT)
        .map_err(|_| HandoffError::Unavailable)?;
    stream
        .set_read_timeout(Some(RESPONSE_TIMEOUT))
        .map_err(|_| HandoffError::Unavailable)?;
    stream
        .set_write_timeout(Some(RECEIVE_TIMEOUT))
        .map_err(|_| HandoffError::Unavailable)?;
    write_frame(&mut stream, &encode_request(request))?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|_| HandoffError::Unavailable)?;
    let response =
        decode_response(&read_frame(&mut stream)?).map_err(|()| HandoffError::Rejected)?;
    let expected_identity = match request {
        Request::Invoked(identity) | Request::Report(identity, _) => identity,
    };
    match response {
        Response::Committed(kind, identity)
            if kind == expected
                && identity.run_id == expected_identity.run_id
                && identity.operation_id == expected_identity.operation_id
                && identity.lease_id == expected_identity.lease_id =>
        {
            Ok(())
        },
        Response::Committed(_, _) | Response::Rejected => Err(HandoffError::Rejected),
    }
}

pub(crate) fn encode_request(request: &Request) -> Vec<u8> {
    let (magic, identity) = match request {
        Request::Invoked(identity) => (INVOKED_MAGIC, identity),
        Request::Report(identity, _) => (REPORT_MAGIC, identity),
    };
    let mut body = magic.to_vec();
    field(&mut body, 1, identity.run_id.as_bytes());
    field(&mut body, 2, identity.operation_id.as_bytes());
    field(&mut body, 3, identity.lease_id.as_bytes());
    field(&mut body, 4, &identity.credential);
    if let Request::Report(_, report) = request {
        match report {
            TerminalHandoffReport::NotAttempted(rejection) => {
                field(&mut body, 5, b"not_attempted");
                field(&mut body, 6, rejection_token(*rejection).as_bytes());
            },
            TerminalHandoffReport::Finalized {
                result,
                receipt_digest,
                receipt_bytes,
            } => {
                field(&mut body, 5, b"finalized");
                field(&mut body, 6, result_token(*result).as_bytes());
                field(&mut body, 7, receipt_digest.as_bytes());
                field(&mut body, 8, receipt_bytes);
            },
        }
    }
    body
}

pub(crate) fn decode_request(body: &[u8]) -> Result<Request, ()> {
    let (kind, records) = if let Some(records) = body.strip_prefix(INVOKED_MAGIC) {
        (AckKind::Invoked, parse_records(records)?)
    } else if let Some(records) = body.strip_prefix(REPORT_MAGIC) {
        (AckKind::Report, parse_records(records)?)
    } else {
        return Err(());
    };
    let expected_count = if kind == AckKind::Invoked {
        4
    } else {
        records.len()
    };
    if records.len() != expected_count || records.len() < 4 {
        return Err(());
    }
    let run_id = ascii(records[0].1)?;
    let operation_id = ascii(records[1].1)?;
    let lease_id = ascii(records[2].1)?;
    if !valid_hex_32(run_id)
        || operation_id != format!("sandbox-{run_id}")
        || !valid_hex_32(lease_id)
    {
        return Err(());
    }
    let credential: [u8; 32] = records[3].1.try_into().map_err(|_| ())?;
    let identity = HandoffIdentity {
        run_id: run_id.into(),
        operation_id: operation_id.into(),
        lease_id: lease_id.into(),
        credential,
    };
    if kind == AckKind::Invoked {
        return Ok(Request::Invoked(identity));
    }
    if records.len() != 6 && records.len() != 8 {
        return Err(());
    }
    let variant = ascii(records[4].1)?;
    let value = ascii(records[5].1)?;
    let report = match variant {
        "not_attempted" if records.len() == 6 => {
            TerminalHandoffReport::NotAttempted(parse_rejection(value)?)
        },
        "finalized" if records.len() == 8 => {
            let result = parse_result(value)?;
            let receipt_digest = ascii(records[6].1)?;
            let receipt_bytes = records[7].1;
            if !valid_hex_64(receipt_digest)
                || receipt_bytes.is_empty()
                || receipt_bytes.len() > RECEIPT_BYTES_MAX
                || lowercase_hex(&Sha256::digest(receipt_bytes)) != receipt_digest
            {
                return Err(());
            }
            TerminalHandoffReport::Finalized {
                result,
                receipt_digest: receipt_digest.into(),
                receipt_bytes: receipt_bytes.to_vec(),
            }
        },
        _ => return Err(()),
    };
    Ok(Request::Report(identity, report))
}

fn encode_response(response: &Response) -> Vec<u8> {
    match response {
        Response::Rejected => REJECTED_MAGIC.to_vec(),
        Response::Committed(kind, identity) => {
            let mut body = match kind {
                AckKind::Invoked => INVOKED_ACK_MAGIC.to_vec(),
                AckKind::Report => REPORT_ACK_MAGIC.to_vec(),
            };
            field(&mut body, 1, identity.run_id.as_bytes());
            field(&mut body, 2, identity.operation_id.as_bytes());
            field(&mut body, 3, identity.lease_id.as_bytes());
            field(&mut body, 4, COMMITTED);
            body
        },
    }
}

fn decode_response(body: &[u8]) -> Result<Response, ()> {
    if body == REJECTED_MAGIC {
        return Ok(Response::Rejected);
    }
    let (kind, records) = if let Some(records) = body.strip_prefix(INVOKED_ACK_MAGIC) {
        (AckKind::Invoked, parse_records(records)?)
    } else if let Some(records) = body.strip_prefix(REPORT_ACK_MAGIC) {
        (AckKind::Report, parse_records(records)?)
    } else {
        return Err(());
    };
    if records.len() != 4 || records[3].1 != COMMITTED {
        return Err(());
    }
    let run_id = ascii(records[0].1)?;
    let operation_id = ascii(records[1].1)?;
    let lease_id = ascii(records[2].1)?;
    if !valid_hex_32(run_id)
        || operation_id != format!("sandbox-{run_id}")
        || !valid_hex_32(lease_id)
    {
        return Err(());
    }
    Ok(Response::Committed(
        kind,
        HandoffIdentity {
            run_id: run_id.into(),
            operation_id: operation_id.into(),
            lease_id: lease_id.into(),
            credential: [0; 32],
        },
    ))
}

fn parse_records(mut bytes: &[u8]) -> Result<Vec<(u8, &[u8])>, ()> {
    let mut records = Vec::with_capacity(8);
    let mut previous = 0_u8;
    while !bytes.is_empty() {
        if bytes.len() < 5 || records.len() == 8 {
            return Err(());
        }
        let number = bytes[0];
        let length = u32::from_be_bytes(bytes[1..5].try_into().map_err(|_| ())?) as usize;
        bytes = &bytes[5..];
        if number <= previous || length > bytes.len() {
            return Err(());
        }
        let (value, remaining) = bytes.split_at(length);
        records.push((number, value));
        previous = number;
        bytes = remaining;
    }
    if records
        .iter()
        .enumerate()
        .any(|(index, (number, _))| *number != u8::try_from(index + 1).unwrap_or(u8::MAX))
    {
        return Err(());
    }
    Ok(records)
}

fn field(body: &mut Vec<u8>, number: u8, value: &[u8]) {
    body.push(number);
    body.extend_from_slice(&u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
    body.extend_from_slice(value);
}

fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, HandoffError> {
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .map_err(|_| HandoffError::Unavailable)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > BODY_BYTES_MAX {
        return Err(HandoffError::Unavailable);
    }
    let mut body = vec![0; length];
    stream
        .read_exact(&mut body)
        .map_err(|_| HandoffError::Unavailable)?;
    let mut trailing = [0_u8; 1];
    if stream
        .read(&mut trailing)
        .map_err(|_| HandoffError::Unavailable)?
        != 0
    {
        return Err(HandoffError::Unavailable);
    }
    Ok(body)
}

fn read_frame_until(stream: &mut TcpStream, deadline: Instant) -> Result<Vec<u8>, HandoffError> {
    let mut length = [0_u8; 4];
    read_exact_until(stream, &mut length, deadline)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > BODY_BYTES_MAX {
        return Err(HandoffError::Unavailable);
    }
    let mut body = vec![0; length];
    read_exact_until(stream, &mut body, deadline)?;
    let mut trailing = [0_u8; 1];
    set_remaining_timeout(stream, deadline)?;
    if stream
        .read(&mut trailing)
        .map_err(|_| HandoffError::Unavailable)?
        != 0
    {
        return Err(HandoffError::Unavailable);
    }
    Ok(body)
}

fn read_exact_until(
    stream: &mut TcpStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), HandoffError> {
    while !bytes.is_empty() {
        set_remaining_timeout(stream, deadline)?;
        match stream.read(bytes) {
            Ok(0) => return Err(HandoffError::Unavailable),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {},
            Err(_) => return Err(HandoffError::Unavailable),
        }
    }
    Ok(())
}

fn set_remaining_timeout(stream: &TcpStream, deadline: Instant) -> Result<(), HandoffError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(HandoffError::Unavailable)?;
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|_| HandoffError::Unavailable)
}

fn write_frame(stream: &mut TcpStream, body: &[u8]) -> Result<(), HandoffError> {
    if body.is_empty() || body.len() > BODY_BYTES_MAX {
        return Err(HandoffError::Unavailable);
    }
    let length = u32::try_from(body.len()).map_err(|_| HandoffError::Unavailable)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(body))
        .and_then(|()| stream.flush())
        .map_err(|_| HandoffError::Unavailable)
}

fn ascii(bytes: &[u8]) -> Result<&str, ()> {
    let text = std::str::from_utf8(bytes).map_err(|_| ())?;
    if text.is_ascii() {
        Ok(text)
    } else {
        Err(())
    }
}

fn valid_hex_32(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn rejection_token(rejection: TargetRejection) -> &'static str {
    match rejection {
        TargetRejection::DeploymentNotFound => "DEPLOYMENT_NOT_FOUND",
        TargetRejection::ContainerNotFound => "CONTAINER_NOT_FOUND",
        TargetRejection::InvalidTarget => "INVALID_TARGET",
    }
}

fn parse_rejection(value: &str) -> Result<TargetRejection, ()> {
    match value {
        "DEPLOYMENT_NOT_FOUND" => Ok(TargetRejection::DeploymentNotFound),
        "CONTAINER_NOT_FOUND" => Ok(TargetRejection::ContainerNotFound),
        "INVALID_TARGET" => Ok(TargetRejection::InvalidTarget),
        _ => Err(()),
    }
}

fn result_token(result: OperationResult) -> &'static str {
    match result {
        OperationResult::Succeeded => "SUCCEEDED",
        OperationResult::Failed => "FAILED",
        OperationResult::Unknown => "UNKNOWN",
    }
}

fn parse_result(value: &str) -> Result<OperationResult, ()> {
    match value {
        "SUCCEEDED" => Ok(OperationResult::Succeeded),
        "FAILED" => Ok(OperationResult::Failed),
        "UNKNOWN" => Ok(OperationResult::Unknown),
        _ => Err(()),
    }
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn unix_time() -> Result<i64, HandoffError> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| HandoffError::Unavailable)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| HandoffError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> HandoffIdentity {
        HandoffIdentity {
            run_id: "0123456789abcdef0123456789abcdef".into(),
            operation_id: "sandbox-0123456789abcdef0123456789abcdef".into(),
            lease_id: "fedcba9876543210fedcba9876543210".into(),
            credential: [7; 32],
        }
    }

    fn private_directory(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one vertical test keeps malformed input, fencing, replay, and recovery contiguous"
    )]
    fn authenticated_transactions_fence_replay_and_bind_terminal_report() {
        let now = unix_time().unwrap();
        let root = std::env::temp_dir().join(format!(
            "kapsel-runner-handoff-{}-{now}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        private_directory(&root);
        private_directory(&root.join("receipts"));
        let service = Arc::new(
            Service::open(
                root.join("sandbox.sqlite3"),
                root.join("receipts"),
                [9; 32],
                now,
            )
            .unwrap(),
        );
        let admission = service
            .admit(&"1".repeat(32), crate::Scenario::Healthy, now)
            .unwrap();
        let lease = service.dispatch_next(now).unwrap();
        rusqlite::Connection::open(root.join("sandbox.sqlite3"))
            .unwrap()
            .execute(
                "UPDATE runs SET policy_verified = 1 WHERE run_id = ?1",
                [&admission.run_id],
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server_service = Arc::clone(&service);
        let server = std::thread::spawn(move || {
            for _ in 0..13 {
                let (stream, _) = listener.accept().unwrap();
                let _ = handle_connection(stream, &server_service);
            }
        });
        let assignment = service.handoff_assignment(&lease, endpoint, now).unwrap();
        let identity = assignment.identity();
        let mut malformed = encode_request(&Request::Invoked(identity.clone()));
        malformed.extend_from_slice(b"secret-input-must-not-reflect");
        let mut stream = TcpStream::connect(endpoint).unwrap();
        write_frame(&mut stream, &malformed).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            decode_response(&read_frame(&mut stream).unwrap()),
            Ok(Response::Rejected)
        );
        let invoked: bool = rusqlite::Connection::open(root.join("sandbox.sqlite3"))
            .unwrap()
            .query_row(
                "SELECT application_invoked FROM runs WHERE run_id = ?1",
                [&admission.run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!invoked);

        let mut oversized_frame = TcpStream::connect(endpoint).unwrap();
        oversized_frame
            .write_all(&u32::try_from(BODY_BYTES_MAX + 1).unwrap().to_be_bytes())
            .unwrap();
        oversized_frame.shutdown(Shutdown::Write).unwrap();
        let mut disconnected = [0_u8; 1];
        assert!(!matches!(oversized_frame.read(&mut disconnected), Ok(1)));

        let oversized_receipt = vec![b'x'; RECEIPT_BYTES_MAX + 1];
        let oversized_report = Request::Report(
            identity.clone(),
            TerminalHandoffReport::Finalized {
                result: OperationResult::Unknown,
                receipt_digest: lowercase_hex(&Sha256::digest(&oversized_receipt)),
                receipt_bytes: oversized_receipt,
            },
        );
        assert_eq!(
            send_request(endpoint, &oversized_report, AckKind::Report),
            Err(HandoffError::Rejected)
        );
        let database = rusqlite::Connection::open(root.join("sandbox.sqlite3")).unwrap();
        let (still_not_invoked, reports): (bool, i64) = database
            .query_row(
                concat!(
                    "SELECT application_invoked, (SELECT COUNT(*) FROM application_reports ",
                    "WHERE run_id = ?1) FROM runs WHERE run_id = ?1"
                ),
                [&admission.run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(!still_not_invoked);
        assert_eq!(reports, 0);

        let mut lost_ack = TcpStream::connect(endpoint).unwrap();
        write_frame(
            &mut lost_ack,
            &encode_request(&Request::Invoked(identity.clone())),
        )
        .unwrap();
        lost_ack.shutdown(Shutdown::Write).unwrap();
        drop(lost_ack);
        for _ in 0..100 {
            let invoked: bool = rusqlite::Connection::open(root.join("sandbox.sqlite3"))
                .unwrap()
                .query_row(
                    "SELECT application_invoked FROM runs WHERE run_id = ?1",
                    [&admission.run_id],
                    |row| row.get(0),
                )
                .unwrap();
            if invoked {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        send_request(
            endpoint,
            &Request::Invoked(identity.clone()),
            AckKind::Invoked,
        )
        .unwrap();
        let page = service.events(&admission.run_id, 0, 64, now + 2).unwrap();
        assert_eq!(page.events.len(), 2);

        let mut wrong = identity.clone();
        wrong.credential[0] ^= 1;
        assert_eq!(
            send_request(endpoint, &Request::Invoked(wrong), AckKind::Invoked),
            Err(HandoffError::Rejected)
        );
        let mut cross_run = identity.clone();
        cross_run.run_id = "ffffffffffffffffffffffffffffffff".into();
        cross_run.operation_id = format!("sandbox-{}", cross_run.run_id);
        assert_eq!(
            send_request(endpoint, &Request::Invoked(cross_run), AckKind::Invoked),
            Err(HandoffError::Rejected)
        );
        let mut cross_lease = identity.clone();
        cross_lease.lease_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
        assert_eq!(
            send_request(endpoint, &Request::Invoked(cross_lease), AckKind::Invoked),
            Err(HandoffError::Rejected)
        );
        let report = TerminalHandoffReport::NotAttempted(TargetRejection::InvalidTarget);
        send_request(
            endpoint,
            &Request::Report(identity.clone(), report.clone()),
            AckKind::Report,
        )
        .unwrap();
        send_request(
            endpoint,
            &Request::Report(identity.clone(), report.clone()),
            AckKind::Report,
        )
        .unwrap();
        assert_eq!(
            service
                .snapshot(&admission.run_id, now + 2)
                .unwrap()
                .target_rejection
                .as_deref(),
            Some("INVALID_TARGET")
        );
        assert_eq!(
            send_request(
                endpoint,
                &Request::Report(
                    identity.clone(),
                    TerminalHandoffReport::NotAttempted(TargetRejection::ContainerNotFound),
                ),
                AckKind::Report,
            ),
            Err(HandoffError::Rejected)
        );

        let recovered = service
            .recover_run(&admission.run_id, Some(&lease), now + 2)
            .unwrap();
        assert_eq!(
            send_request(endpoint, &Request::Invoked(identity), AckKind::Invoked),
            Err(HandoffError::Rejected)
        );
        let recovered_assignment = service
            .handoff_assignment(&recovered, endpoint, now + 2)
            .unwrap();
        send_request(
            endpoint,
            &Request::Report(recovered_assignment.identity(), report),
            AckKind::Report,
        )
        .unwrap();
        server.join().unwrap();

        let connection = rusqlite::Connection::open(root.join("sandbox.sqlite3")).unwrap();
        let verifier: Vec<u8> = connection
            .query_row(
                "SELECT handoff_credential_verifier FROM runs WHERE run_id = ?1",
                [&admission.run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(verifier.len(), 32);
        assert_ne!(verifier, recovered_assignment.credential);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one recovery test spans report binding, expiry, restart, replacement, and cleanup"
    )]
    fn pending_finalized_report_survives_public_expiry_and_releases_capacity() {
        let now = 1_774_051_200_i64;
        let root = std::env::temp_dir().join(format!(
            "kapsel-runner-expired-pending-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        private_directory(&root);
        private_directory(&root.join("receipts"));
        let database = root.join("sandbox.sqlite3");
        let service = Service::open(&database, root.join("receipts"), [9; 32], now).unwrap();
        let admission = service
            .admit(&"6".repeat(32), crate::Scenario::Healthy, now)
            .unwrap();
        let lease = service.dispatch_next(now + 1).unwrap();
        let specification = service.provisioning_specification(&lease, now + 1).unwrap();
        let namespace_uid = "expiry-namespace-uid";
        let objects = specification
            .required_objects
            .iter()
            .enumerate()
            .map(|(index, object)| crate::ProvisionedObject {
                identity: object.identity.clone(),
                uid: if index == 0 {
                    namespace_uid.into()
                } else {
                    format!("expiry-object-{index}")
                },
                owner_label: specification.cleanup_identity.clone(),
                content_digest: object.content_digest.clone(),
            })
            .collect::<Vec<_>>();
        service
            .verify_provisioned_target(
                &lease,
                &crate::ProvisionedTarget {
                    namespace_uid: namespace_uid.into(),
                    policy_revision: specification.policy_revision.clone(),
                    policy_inventory_digest: specification.policy_inventory_digest.clone(),
                    cleanup_identity: specification.cleanup_identity.clone(),
                    objects,
                },
                now + 1,
            )
            .unwrap();
        let assignment = service
            .handoff_assignment(&lease, "127.0.0.1:1".parse().unwrap(), now + 1)
            .unwrap();
        let identity = assignment.identity();
        service
            .commit_application_invoked(&identity, now + 1)
            .unwrap();
        let bytes = b"frozen receipt across public expiry".to_vec();
        let report = TerminalHandoffReport::Finalized {
            result: OperationResult::Unknown,
            receipt_digest: lowercase_hex(&Sha256::digest(&bytes)),
            receipt_bytes: bytes,
        };
        let receipt_directory = root.join("receipts");
        let held_receipts = root.join("receipts-held");
        std::fs::rename(&receipt_directory, &held_receipts).unwrap();
        std::fs::write(&receipt_directory, b"block publication").unwrap();
        assert_eq!(
            service.commit_application_report(&identity, &report, now + 2),
            Err(crate::ServiceError::Unavailable)
        );
        std::fs::remove_file(&receipt_directory).unwrap();
        std::fs::rename(&held_receipts, &receipt_directory).unwrap();
        service.sweep_retention(now + 86_401).unwrap();
        let pending: i64 = rusqlite::Connection::open(&database)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM receipt_publications WHERE run_id = ?1",
                [&admission.run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending, 1);
        drop(service);

        let service = Service::open(&database, &receipt_directory, [9; 32], now + 86_402).unwrap();
        let pending_after_restart: i64 = rusqlite::Connection::open(&database)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM receipt_publications WHERE run_id = ?1",
                [&admission.run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending_after_restart, 1);
        let recovered = service
            .recover_run(&admission.run_id, None, now + 86_402)
            .unwrap();
        let replacement = service
            .handoff_assignment(&recovered, "127.0.0.1:1".parse().unwrap(), now + 86_402)
            .unwrap();
        service
            .commit_application_report(&replacement.identity(), &report, now + 86_402)
            .unwrap();
        assert!(std::fs::read_dir(&receipt_directory)
            .unwrap()
            .next()
            .is_none());
        let eligible: bool = rusqlite::Connection::open(&database)
            .unwrap()
            .query_row(
                "SELECT eligible FROM cleanup_records WHERE run_id = ?1",
                [&admission.run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(eligible);
        service
            .start_cleanup(
                &admission.run_id,
                &specification.cleanup_identity,
                namespace_uid,
                now + 86_403,
            )
            .unwrap();
        let connection = rusqlite::Connection::open(&database).unwrap();
        let mut statement = connection
            .prepare(
                "SELECT identity, uid, owner_label FROM provisioned_object_owners \
                 WHERE run_id = ?1",
            )
            .unwrap();
        let objects = statement
            .query_map([&admission.run_id], |row| {
                let identity = row.get::<_, String>(0)?;
                let (kind, namespace, name) = crate::object_identity_parts(&identity)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                Ok(crate::CleanupObjectAbsence {
                    kind,
                    namespace,
                    name,
                    uid: row.get(1)?,
                    owner_label: row.get(2)?,
                    present: false,
                })
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        drop(statement);
        drop(connection);
        let absence = crate::CleanupAbsenceEvidence {
            namespace_uid: namespace_uid.into(),
            objects,
        };
        service
            .complete_cleanup(
                &admission.run_id,
                &specification.cleanup_identity,
                &absence,
                now + 86_404,
            )
            .unwrap();
        assert!(service.recoverable_runs().unwrap().is_empty());
        let connection = rusqlite::Connection::open(&database).unwrap();
        let active: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM runs WHERE run_id = ?1 AND active = 1",
                [&admission.run_id],
                |row| row.get(0),
            )
            .unwrap();
        let live_verifier: i64 = connection
            .query_row(
                concat!(
                    "SELECT COUNT(*) FROM runs WHERE run_id = ?1 ",
                    "AND length(handoff_credential_verifier) != 0"
                ),
                [&admission.run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(active, 0);
        assert_eq!(live_verifier, 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table-driven test keeps all receiver results and exact replay seams together"
    )]
    fn finalized_results_publish_exact_bytes_once_across_restart_and_replacement_lease() {
        for (index, result) in [
            OperationResult::Succeeded,
            OperationResult::Failed,
            OperationResult::Unknown,
        ]
        .into_iter()
        .enumerate()
        {
            let now = unix_time().unwrap();
            let root = std::env::temp_dir().join(format!(
                "kapsel-runner-finalized-{}-{index}-{now}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            private_directory(&root);
            private_directory(&root.join("receipts"));
            let service = Service::open(
                root.join("sandbox.sqlite3"),
                root.join("receipts"),
                [9; 32],
                now,
            )
            .unwrap();
            let admission = service
                .admit(
                    &format!("{:032x}", index + 1),
                    crate::Scenario::Healthy,
                    now,
                )
                .unwrap();
            let lease = service.dispatch_next(now).unwrap();
            rusqlite::Connection::open(root.join("sandbox.sqlite3"))
                .unwrap()
                .execute(
                    "UPDATE runs SET policy_verified = 1 WHERE run_id = ?1",
                    [&admission.run_id],
                )
                .unwrap();
            let assignment = service
                .handoff_assignment(&lease, "127.0.0.1:1".parse().unwrap(), now)
                .unwrap();
            let identity = assignment.identity();
            service.commit_application_invoked(&identity, now).unwrap();
            let bytes = format!("exact-{result:?}-receipt").into_bytes();
            let digest = lowercase_hex(&Sha256::digest(&bytes));
            let report = TerminalHandoffReport::Finalized {
                result,
                receipt_digest: digest,
                receipt_bytes: bytes.clone(),
            };
            service
                .commit_application_report(&identity, &report, now)
                .unwrap();
            service
                .commit_application_report(&identity, &report, now)
                .unwrap();
            assert_eq!(service.receipt(&admission.run_id, now).unwrap(), bytes);
            let snapshot = service.snapshot(&admission.run_id, now).unwrap();
            assert_eq!(
                snapshot.receiver_result.as_deref(),
                Some(result_token(result))
            );
            assert!(snapshot.receipt_available);

            let changed_bytes = b"changed receipt".to_vec();
            let changed = TerminalHandoffReport::Finalized {
                result,
                receipt_digest: lowercase_hex(&Sha256::digest(&changed_bytes)),
                receipt_bytes: changed_bytes,
            };
            let exact_service = service.clone();
            let changed_service = service.clone();
            let exact_identity = identity.clone();
            let changed_identity = identity.clone();
            let exact_report = report.clone();
            let changed_report = changed.clone();
            let exact = std::thread::spawn(move || {
                exact_service.commit_application_report(&exact_identity, &exact_report, now)
            });
            let mismatch = std::thread::spawn(move || {
                changed_service.commit_application_report(&changed_identity, &changed_report, now)
            });
            assert_eq!(exact.join().unwrap(), Ok(()));
            assert_eq!(
                mismatch.join().unwrap(),
                Err(crate::ServiceError::Unavailable)
            );
            drop(service);

            let service = Service::open(
                root.join("sandbox.sqlite3"),
                root.join("receipts"),
                [9; 32],
                now,
            )
            .unwrap();
            let recovered = service
                .recover_run(&admission.run_id, Some(&lease), now + 1)
                .unwrap();
            let replacement = service
                .handoff_assignment(&recovered, "127.0.0.1:1".parse().unwrap(), now + 1)
                .unwrap();
            service
                .commit_application_report(&replacement.identity(), &report, now + 1)
                .unwrap();
            assert_eq!(service.receipt(&admission.run_id, now + 1).unwrap(), bytes);
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    fn deliver_after_expiry(
        service: Service,
        request: &Request,
        expiry: i64,
        database: &std::path::Path,
        run_id: &str,
    ) -> Response {
        rusqlite::Connection::open(database)
            .unwrap()
            .execute(
                "UPDATE runs SET lease_expires_at = ?2 WHERE run_id = ?1",
                rusqlite::params![run_id, expiry],
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_connection(stream, &service).unwrap();
        });
        let body = encode_request(request);
        let mut stream = TcpStream::connect(endpoint).unwrap();
        stream
            .write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
            .unwrap();
        stream.write_all(&body[..body.len() - 1]).unwrap();
        std::thread::sleep(Duration::from_millis(1_200));
        stream.write_all(&body[body.len() - 1..]).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let response = decode_response(&read_frame(&mut stream).unwrap()).unwrap();
        server.join().unwrap();
        response
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one test proves expiry at the complete-frame transaction seam"
    )]
    fn invocation_and_report_connected_before_expiry_fail_after_complete_parse() {
        let now = unix_time().unwrap();
        let root = std::env::temp_dir().join(format!(
            "kapsel-runner-cross-expiry-{}-{now}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        private_directory(&root);
        private_directory(&root.join("receipts"));
        let database = root.join("sandbox.sqlite3");
        let service = Service::open(&database, root.join("receipts"), [9; 32], now).unwrap();

        let invocation_run = service
            .admit(&"4".repeat(32), crate::Scenario::Healthy, now)
            .unwrap();
        let invocation_lease = service.dispatch_next(now).unwrap();
        rusqlite::Connection::open(&database)
            .unwrap()
            .execute(
                "UPDATE runs SET policy_verified = 1 WHERE run_id = ?1",
                [&invocation_run.run_id],
            )
            .unwrap();
        let invocation_assignment = service
            .handoff_assignment(&invocation_lease, "127.0.0.1:1".parse().unwrap(), now)
            .unwrap();
        let invocation_identity = invocation_assignment.identity();
        let expiry = unix_time().unwrap() + 1;
        assert_eq!(
            deliver_after_expiry(
                service.clone(),
                &Request::Invoked(invocation_identity),
                expiry,
                &database,
                &invocation_run.run_id,
            ),
            Response::Rejected
        );
        let invoked: bool = rusqlite::Connection::open(&database)
            .unwrap()
            .query_row(
                "SELECT application_invoked FROM runs WHERE run_id = ?1",
                [&invocation_run.run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!invoked);
        let invocation_recovery = service
            .recover_run(
                &invocation_run.run_id,
                Some(&invocation_lease),
                unix_time().unwrap(),
            )
            .unwrap();
        let invocation_specification = service
            .provisioning_specification(&invocation_recovery, unix_time().unwrap())
            .unwrap();
        service
            .record_setup_failure_without_resources(
                &invocation_recovery,
                &invocation_specification.cleanup_identity,
                unix_time().unwrap(),
            )
            .unwrap();

        let report_run = service
            .admit(
                &"5".repeat(32),
                crate::Scenario::Healthy,
                unix_time().unwrap(),
            )
            .unwrap();
        let report_lease = service.dispatch_next(unix_time().unwrap()).unwrap();
        rusqlite::Connection::open(&database)
            .unwrap()
            .execute(
                "UPDATE runs SET policy_verified = 1 WHERE run_id = ?1",
                [&report_run.run_id],
            )
            .unwrap();
        let report_assignment = service
            .handoff_assignment(
                &report_lease,
                "127.0.0.1:1".parse().unwrap(),
                unix_time().unwrap(),
            )
            .unwrap();
        let report_identity = report_assignment.identity();
        service
            .commit_application_invoked(&report_identity, unix_time().unwrap())
            .unwrap();
        let expiry = unix_time().unwrap() + 1;
        assert_eq!(
            deliver_after_expiry(
                service.clone(),
                &Request::Report(
                    report_identity,
                    TerminalHandoffReport::NotAttempted(TargetRejection::InvalidTarget),
                ),
                expiry,
                &database,
                &report_run.run_id,
            ),
            Response::Rejected
        );
        assert_eq!(
            service
                .snapshot(&report_run.run_id, unix_time().unwrap())
                .unwrap()
                .execution_state,
            crate::ExecutionState::Running
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn trickled_request_cannot_extend_the_absolute_five_second_frame_deadline() {
        let now = unix_time().unwrap();
        let root = std::env::temp_dir().join(format!(
            "kapsel-runner-trickle-{}-{now}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        private_directory(&root);
        private_directory(&root.join("receipts"));
        let service = Service::open(
            root.join("sandbox.sqlite3"),
            root.join("receipts"),
            [9; 32],
            now,
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_connection(stream, &service)
        });
        let body = encode_request(&Request::Invoked(identity()));
        let mut stream = TcpStream::connect(endpoint).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
            .unwrap();
        let started = Instant::now();
        for byte in body.iter().take(6) {
            std::thread::sleep(Duration::from_millis(900));
            if stream.write_all(std::slice::from_ref(byte)).is_err() {
                break;
            }
        }
        let mut response = [0_u8; 1];
        assert!(stream.read(&mut response).is_err() || response == [0]);
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_secs(5));
        assert!(elapsed < Duration::from_secs(7));
        assert_eq!(server.join().unwrap(), Err(HandoffError::Unavailable));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn credential_bearing_debug_output_is_redacted() {
        let mut private = identity();
        for (index, byte) in private.credential.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap();
        }
        let identity_debug = format!("{private:?}");
        let request_debug = format!("{:?}", Request::Invoked(private.clone()));
        let response_debug = format!("{:?}", Response::Committed(AckKind::Invoked, private));
        for debug in [identity_debug, request_debug, response_debug] {
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains("0, 1, 2, 3, 4, 5"));
        }
    }

    #[test]
    fn codec_rejects_hostile_records_and_preserves_exact_receipt() {
        let bytes = b"exact receipt".to_vec();
        let digest = lowercase_hex(&Sha256::digest(&bytes));
        for request in [
            Request::Invoked(identity()),
            Request::Report(
                identity(),
                TerminalHandoffReport::NotAttempted(TargetRejection::InvalidTarget),
            ),
            Request::Report(
                identity(),
                TerminalHandoffReport::Finalized {
                    result: OperationResult::Unknown,
                    receipt_digest: digest,
                    receipt_bytes: bytes,
                },
            ),
        ] {
            let encoded = encode_request(&request);
            assert_eq!(decode_request(&encoded), Ok(request));
            for mutation in [
                Vec::new(),
                encoded[..encoded.len() - 1].to_vec(),
                [encoded.as_slice(), b"trailing"].concat(),
            ] {
                assert_eq!(decode_request(&mutation), Err(()));
            }
        }
    }

    #[test]
    fn codec_rejects_duplicate_reordered_unknown_and_changed_digest() {
        let canonical = encode_request(&Request::Invoked(identity()));
        let magic_length = INVOKED_MAGIC.len();
        let first_length = 5 + 32;
        let first = &canonical[magic_length..magic_length + first_length];
        let remainder = &canonical[magic_length + first_length..];
        assert!(
            decode_request(&[&canonical[..magic_length], first, first, remainder].concat())
                .is_err()
        );
        let mut reordered = canonical.clone();
        reordered[magic_length] = 2;
        assert!(decode_request(&reordered).is_err());
        let mut unknown = canonical;
        unknown.extend_from_slice(&[9, 0, 0, 0, 0]);
        assert!(decode_request(&unknown).is_err());

        let bytes = b"receipt".to_vec();
        let report = Request::Report(
            identity(),
            TerminalHandoffReport::Finalized {
                result: OperationResult::Succeeded,
                receipt_digest: "0".repeat(64),
                receipt_bytes: bytes,
            },
        );
        assert!(decode_request(&encode_request(&report)).is_err());
    }
}
