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
/// 40 KiB before allocation. This function checks framing, not JSON content or protocol version.
/// Call [`validate_response_version`] before using the response. A failure never establishes
/// non-admission.
///
/// # Errors
///
/// Returns a bounded local transport error for invalid request size, connection, exchange or
/// response framing failure.
pub fn exchange(socket: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
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
    let length = u32::try_from(request.len()).map_err(|_| Error::Exchange)?;
    stream
        .write_all(&length.to_be_bytes())
        .map_err(|_| Error::Exchange)?;
    stream.write_all(request).map_err(|_| Error::Exchange)?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|_| Error::Exchange)?;
    let mut prefix = [0_u8; 4];
    stream
        .read_exact(&mut prefix)
        .map_err(|_| Error::Exchange)?;
    let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| Error::Response)?;
    if length == 0 || length > RESPONSE_BYTES_MAX {
        return Err(Error::Response);
    }
    let mut response = vec![0_u8; length];
    stream
        .read_exact(&mut response)
        .map_err(|_| Error::Exchange)?;
    let mut trailing = [0_u8; 1];
    if stream.read(&mut trailing).map_err(|_| Error::Exchange)? != 0 {
        return Err(Error::Response);
    }
    Ok(response)
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
pub fn validate_response_version(bytes: &[u8]) -> Result<String, Error> {
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
