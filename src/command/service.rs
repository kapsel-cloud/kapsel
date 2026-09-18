//! Operator-only preparation of the existing service document, with no publication or history I/O.

use super::{
    finish_options, read_bounded, read_exact_32, take_path, write_new_private, BTreeMap,
    CommandError, CommandResult, ErrorClass, OsString, PathBuf,
};

const DOCUMENT_BYTES_MAX: usize = 160 * 1024;
const PREPARE: &str = "prepare-service-config";
const VALIDATE: &str = "validate-service-config";

pub(super) fn prepare(mut arguments: impl Iterator<Item = OsString>) -> CommandResult {
    let mut keys = Vec::new();
    let mut approvals = Vec::new();
    let mut signer = None;
    let mut output = None;
    while let Some(option) = arguments.next() {
        match option.to_str() {
            Some("--authorization-key") if keys.len() < 128 => {
                let id = text(&mut arguments)?;
                let path = path(&mut arguments)?;
                let public = read_exact_32(&path, PREPARE, ErrorClass::OperatorConfiguration)?;
                keys.push(serde_json::json!({"key_id": id, "public_key_hex": hex(&public)}));
            },
            Some("--approval") if approvals.len() < 32 => {
                let label = text(&mut arguments)?;
                let path = path(&mut arguments)?;
                let grant = read_bounded(&path, 4096, PREPARE, ErrorClass::OperatorConfiguration)?;
                approvals.push(serde_json::json!({
                    "label": label, "signed_grant_hex": hex(&grant),
                }));
            },
            Some("--receipt-signing-key-id") if signer.is_none() => {
                signer = Some(text(&mut arguments)?);
            },
            Some("--output") if output.is_none() => {
                output = Some(path(&mut arguments)?);
            },
            _ => return Err(CommandError::input(PREPARE)),
        }
    }
    let signer = signer.ok_or_else(|| CommandError::input(PREPARE))?;
    let output = output.ok_or_else(|| CommandError::input(PREPARE))?;
    // Array counts and per-input limits bound serialization even before the document-size check.
    let mut bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "service_configuration_version": 1,
        "authorization_keys": keys,
        "approvals": approvals,
        "receipt_signing_key_id": signer,
    }))
    .map_err(|_| CommandError::configuration(PREPARE))?;
    bytes.push(b'\n');
    validate_bytes(&bytes, PREPARE)?;
    write_new_private(&output, &bytes).map_err(|_| CommandError::configuration(PREPARE))?;
    Ok(format!(
        "{{\"command\":\"{PREPARE}\",\"status\":\"PREPARED\"}}"
    ))
}

fn text(arguments: &mut impl Iterator<Item = OsString>) -> Result<String, CommandError> {
    let value = arguments
        .next()
        .ok_or_else(|| CommandError::input(PREPARE))?
        .into_string()
        .map_err(|_| CommandError::input(PREPARE))?;
    if value.len() > 128 {
        return Err(CommandError::input(PREPARE));
    }
    Ok(value)
}

fn path(arguments: &mut impl Iterator<Item = OsString>) -> Result<PathBuf, CommandError> {
    arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| CommandError::input(PREPARE))
}

pub(super) fn validate(mut options: BTreeMap<String, OsString>) -> CommandResult {
    let path = take_path(&mut options, "--operator-config", VALIDATE)?;
    finish_options(&options, VALIDATE)?;
    let bytes = read_bounded(
        &path,
        DOCUMENT_BYTES_MAX,
        VALIDATE,
        ErrorClass::CommandInput,
    )?;
    validate_bytes(&bytes, VALIDATE)?;
    Ok(format!(
        "{{\"command\":\"{VALIDATE}\",\"status\":\"VALIDATED_STATIC\"}}"
    ))
}

fn validate_bytes(bytes: &[u8], command: &'static str) -> Result<(), CommandError> {
    // Parsing accepts a path from its caller, but static validation never accesses it.
    let document = kapsel::parse_service_operator_document(
        bytes,
        PathBuf::from("/var/lib/kapsel/journal.sqlite3"),
    )
    .map_err(|_| CommandError::configuration(command))?;
    kapsel::ServiceApplication::validate_static_configuration(&document.configuration)
        .map_err(|_| CommandError::configuration(command))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}")
            .unwrap_or_else(|_| unreachable!("writing to a String cannot fail"));
    }
    output
}
