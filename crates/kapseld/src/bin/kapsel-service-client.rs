//! Fixed capability-specific client for the Kapsel service.

use std::{
    fs::OpenOptions,
    io::{Read as _, Write as _},
    net::Shutdown,
    os::unix::{
        fs::{OpenOptionsExt as _, PermissionsExt as _},
        net::UnixStream,
    },
    path::Path,
    process::ExitCode,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};

const SOCKET: &str = "/run/kapsel/kapseld.sock";
const RESPONSE_BYTES_MAX: usize = 40 * 1024;
const IO_DEADLINE: Duration = Duration::from_secs(2);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyReceipt {
    version: u8,
    status: String,
    receipt_hex: String,
    receipt_sha256: String,
}

#[derive(Serialize)]
struct SavedReceipt<'a> {
    version: u8,
    status: &'static str,
    receipt_sha256: &'a str,
    output: &'a str,
}

const HELP: &str = "kapsel-service-client: select approved actions and read stored evidence
Usage:
  kapsel-service-client --help | --version
  kapsel-service-client list [after-id]
  kapsel-service-client history [after-id]
  kapsel-service-client submit <operation-id>
  kapsel-service-client status <operation-id>
  kapsel-service-client receipt <operation-id> <new-absolute-output-file>
Exit 0: response delivered, not action success. Exit 2: usage. Exit 4: local failure.
After uncertain submission, read the same ID. Never invent a replacement ID.";

#[derive(Debug)]
enum ClientError {
    Usage,
    Connection,
    Exchange,
    Response,
    ReceiptUnavailable,
    Export,
    Output,
}

impl ClientError {
    const fn diagnostic(&self) -> &'static str {
        match self {
            Self::Usage => "invalid_usage: use kapsel-service-client --help",
            Self::Connection => {
                "connection_unavailable: ask the operator to check service and access"
            },
            Self::Exchange => "exchange_incomplete: read the same ID before deciding what to do",
            Self::Response => "response_invalid: check binary compatibility; read the same ID",
            Self::ReceiptUnavailable => "receipt_unavailable: read status for the same ID",
            Self::Export => "export_failed: inspect the destination; use a new writable path",
            Self::Output => {
                "output_unavailable: restore stdout; read the same ID after uncertainty"
            },
        }
    }
}

impl From<std::io::Error> for ClientError {
    fn from(_: std::io::Error) -> Self {
        Self::Exchange
    }
}

fn main() -> ExitCode {
    let arguments = std::env::args_os()
        .skip(1)
        .map(|argument| argument.into_string().map_err(|_| ClientError::Usage))
        .collect::<Result<Vec<_>, _>>();
    match arguments.and_then(|arguments| run(&arguments)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(
                std::io::stderr(),
                "kapsel-service-client: {}",
                error.diagnostic()
            );
            ExitCode::from(if matches!(error, ClientError::Usage) {
                2
            } else {
                4
            })
        },
    }
}

fn run(arguments: &[String]) -> Result<(), ClientError> {
    if let [argument] = arguments {
        let text = match argument.as_str() {
            "--help" => Some(HELP.to_owned()),
            "--version" => Some(format!(
                "kapsel-service-client {}",
                env!("CARGO_PKG_VERSION")
            )),
            _ => None,
        };
        if let Some(text) = text {
            return writeln!(std::io::stdout(), "{text}").map_err(|_| ClientError::Output);
        }
    }
    let (request, output) = request(arguments).map_err(|()| ClientError::Usage)?;
    #[cfg(feature = "test-harness")]
    let test_socket = std::env::var("KAPSELD_TEST_CLIENT_SOCKET").ok();
    #[cfg(feature = "test-harness")]
    let socket = test_socket.as_deref().unwrap_or(SOCKET);
    #[cfg(not(feature = "test-harness"))]
    let socket = SOCKET;
    let response = exchange(socket, &request)?;
    let status = validate_response_version(&response).map_err(|()| ClientError::Response)?;
    match output {
        None => {
            std::io::stdout()
                .write_all(&response)
                .map_err(|_| ClientError::Output)?;
            std::io::stdout()
                .write_all(b"\n")
                .map_err(|_| ClientError::Output)?;
        },
        Some(_) if status != "READY" => return Err(ClientError::ReceiptUnavailable),
        Some(path) => save_receipt(&response, path)?,
    }
    Ok(())
}

fn request(arguments: &[String]) -> Result<(Vec<u8>, Option<&Path>), ()> {
    let (request, output) = match arguments {
        [command] | [command, _] if command == "list" || command == "history" => {
            let after = arguments.get(1);
            if after.is_some_and(|id| !kapsel_authority::identity_is_valid(id)) {
                return Err(());
            }
            let name = if command == "list" {
                "list_approved_actions"
            } else {
                "list_operation_history"
            };
            (json!({"version":1,"request":name,"after":after}), None)
        },
        [command, id] if command == "status" || command == "submit" => {
            if !kapsel_authority::identity_is_valid(id) {
                return Err(());
            }
            let name = if command == "status" {
                "get_set_deployment_image_status"
            } else {
                "submit_set_deployment_image"
            };
            (json!({"version":1,"request":name,"operation_id":id}), None)
        },
        [command, id, output] if command == "receipt" => {
            if !kapsel_authority::identity_is_valid(id) || !Path::new(output).is_absolute() {
                return Err(());
            }
            (
                json!({"version":1,"request":"get_set_deployment_image_receipt","operation_id":id}),
                Some(Path::new(output)),
            )
        },
        _ => return Err(()),
    };
    Ok((serde_json::to_vec(&request).map_err(|_| ())?, output))
}

fn validate_response_version(bytes: &[u8]) -> Result<String, ()> {
    #[derive(Deserialize)]
    struct ResponseHeader {
        version: u8,
        status: String,
    }
    if bytes.is_empty()
        || bytes.len() > RESPONSE_BYTES_MAX
        || bytes.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{')
    {
        return Err(());
    }
    let header: ResponseHeader = serde_json::from_slice(bytes).map_err(|_| ())?;
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
        return Err(());
    }
    Ok(header.status)
}

fn exchange(socket: &str, request: &[u8]) -> Result<Vec<u8>, ClientError> {
    let mut stream = UnixStream::connect(socket).map_err(|_| ClientError::Connection)?;
    stream.set_read_timeout(Some(IO_DEADLINE))?;
    stream.set_write_timeout(Some(IO_DEADLINE))?;
    let length = u32::try_from(request.len())
        .map_err(|_| std::io::Error::other("service request is too large"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(request)?;
    stream.shutdown(Shutdown::Write)?;

    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix)?;
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| std::io::Error::other("service response is too large"))?;
    if length == 0 || length > RESPONSE_BYTES_MAX {
        return Err(ClientError::Response);
    }
    let mut response = vec![0_u8; length];
    stream.read_exact(&mut response)?;
    let mut trailing = [0_u8; 1];
    if stream.read(&mut trailing)? != 0 {
        return Err(ClientError::Response);
    }
    Ok(response)
}

fn save_receipt(response: &[u8], path: &Path) -> Result<(), ClientError> {
    let ready: ReadyReceipt =
        serde_json::from_slice(response).map_err(|_| ClientError::Response)?;
    if ready.version != 1 || ready.status != "READY" || !lowercase_sha256(&ready.receipt_sha256) {
        return Err(ClientError::Response);
    }
    let bytes = decode_lowercase_hex(&ready.receipt_hex).map_err(|()| ClientError::Response)?;
    let expected_digest =
        decode_lowercase_hex(&ready.receipt_sha256).map_err(|()| ClientError::Response)?;
    if Sha256::digest(&bytes).as_slice() != expected_digest {
        return Err(ClientError::Response);
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| ClientError::Export)?;
    output
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| ClientError::Export)?;
    if output
        .metadata()
        .map_err(|_| ClientError::Export)?
        .permissions()
        .mode()
        & 0o7777
        != 0o600
    {
        return Err(ClientError::Export);
    }
    output.write_all(&bytes).map_err(|_| ClientError::Export)?;
    output.sync_all().map_err(|_| ClientError::Export)?;
    let path = path.to_str().ok_or(ClientError::Usage)?;
    let report = serde_json::to_vec(&SavedReceipt {
        version: 1,
        status: "READY",
        receipt_sha256: &ready.receipt_sha256,
        output: path,
    })
    .map_err(|_| ClientError::Output)?;
    std::io::stdout()
        .write_all(&report)
        .map_err(|_| ClientError::Output)?;
    std::io::stdout()
        .write_all(b"\n")
        .map_err(|_| ClientError::Output)?;
    Ok(())
}

fn lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn decode_lowercase_hex(value: &str) -> Result<Vec<u8>, ()> {
    if !value.len().is_multiple_of(2)
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or(())?;
            let low = hex_nibble(pair[1]).ok_or(())?;
            Ok((high << 4) | low)
        })
        .collect()
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "controlled client fixtures must fail immediately"
)]
mod tests {
    use super::*;

    #[test]
    fn fixed_grammar_has_only_five_id_only_commands() {
        let status = vec!["status".into(), "op-1".into()];
        let receipt = vec!["receipt".into(), "op-1".into(), "/tmp/receipt".into()];
        let submit = vec![
            "submit".into(),
            "op-1".into(),
            "demo".into(),
            "agent-api".into(),
            "api".into(),
            concat!(
                "registry.example/agent-api@sha256:",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .into(),
        ];
        assert!(request(&status).is_ok());
        assert!(request(&receipt).is_ok());
        assert!(request(&submit).is_err());
        for args in [
            vec!["submit", "op-1"],
            vec!["list"],
            vec!["list", "op-1"],
            vec!["history"],
            vec!["history", "op-1"],
        ] {
            let args = args.into_iter().map(String::from).collect::<Vec<_>>();
            let (bytes, _) = request(&args).unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["version"],
                1
            );
        }
        assert!(request(&[]).is_err());
        assert!(request(&["receipt".into(), "op-1".into()]).is_err());
        assert!(request(&["unknown".into(), "op-1".into()]).is_err());
    }

    #[test]
    fn response_requires_integer_version_one_and_an_object() {
        assert!(validate_response_version(br#"{"version":1,"status":"INDETERMINATE"}"#).is_ok());
        for invalid in [
            r#"{"status":"ADMITTED"}"#,
            r#"{"version":2,"status":"ADMITTED"}"#,
            r#"{"version":1.0,"status":"ADMITTED"}"#,
            r#"{"version":"1","status":"ADMITTED"}"#,
            r#"{"version":1,"version":1,"status":"ADMITTED"}"#,
            r#"[1,"ADMITTED"]"#,
            r#"{"version":1,"status":"ACCEPTED"}"#,
        ] {
            assert!(validate_response_version(invalid.as_bytes()).is_err());
        }
    }

    #[test]
    fn receipt_hex_and_digest_grammar_is_exact() {
        assert_eq!(decode_lowercase_hex("00abff").unwrap(), [0, 0xab, 0xff]);
        assert!(decode_lowercase_hex("0").is_err());
        assert!(decode_lowercase_hex("AB").is_err());
        assert!(decode_lowercase_hex("gg").is_err());
        assert!(lowercase_sha256(&"a".repeat(64)));
        assert!(!lowercase_sha256(&"A".repeat(64)));
    }
}
