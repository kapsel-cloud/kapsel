//! Operator-only preparation of the existing service document, with no publication or history I/O.

use super::{
    finish_options, read_bounded, read_exact_32, take_path, write_new_private, BTreeMap,
    CommandError, CommandResult, ErrorClass, OsString, PathBuf,
};

const DOCUMENT_BYTES_MAX: usize = 160 * 1024;
const PREPARE: &str = "prepare-service-config";
const VALIDATE: &str = "validate-service-config";

pub(super) fn prepare(mut arguments: impl Iterator<Item = OsString>) -> CommandResult {
    let mut authorization_keys = Vec::new();
    let mut approvals = Vec::new();
    let mut receipt_signing_key_id = None;
    let mut output_path = None;

    while let Some(option) = arguments.next() {
        match option.to_str() {
            Some("--authorization-key") if authorization_keys.len() < 128 => {
                let key_id = take_text_argument(&mut arguments)?;
                let key_path = take_path_argument(&mut arguments)?;
                let public_key =
                    read_exact_32(&key_path, PREPARE, ErrorClass::OperatorConfiguration)?;
                let public_key_hex = encode_hex(&public_key);
                authorization_keys.push(serde_json::json!({
                    "key_id": key_id, "public_key_hex": public_key_hex,
                }));
            },
            Some("--approval") if approvals.len() < 32 => {
                let label = take_text_argument(&mut arguments)?;
                let grant_path = take_path_argument(&mut arguments)?;
                let signed_grant = read_bounded(
                    &grant_path,
                    4096,
                    PREPARE,
                    ErrorClass::OperatorConfiguration,
                )?;
                let signed_grant_hex = encode_hex(&signed_grant);
                approvals.push(serde_json::json!({
                    "label": label, "signed_grant_hex": signed_grant_hex,
                }));
            },
            Some("--receipt-signing-key-id") if receipt_signing_key_id.is_none() => {
                receipt_signing_key_id = Some(take_text_argument(&mut arguments)?);
            },
            Some("--output") if output_path.is_none() => {
                output_path = Some(take_path_argument(&mut arguments)?);
            },
            _ => return Err(CommandError::input(PREPARE)),
        }
    }

    let receipt_signing_key_id =
        receipt_signing_key_id.ok_or_else(|| CommandError::input(PREPARE))?;
    let output_path = output_path.ok_or_else(|| CommandError::input(PREPARE))?;

    // Array counts and per-input limits bound serialization even before the document-size check.
    let mut bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "service_configuration_version": 1,
        "authorization_keys": authorization_keys,
        "approvals": approvals,
        "receipt_signing_key_id": receipt_signing_key_id,
    }))
    .map_err(|_| CommandError::configuration(PREPARE))?;
    bytes.push(b'\n');
    validate_document_bytes(&bytes, PREPARE)?;

    write_new_private(&output_path, &bytes).map_err(|_| CommandError::configuration(PREPARE))?;
    Ok(format!(
        "{{\"command\":\"{PREPARE}\",\"status\":\"PREPARED\"}}"
    ))
}

pub(super) fn validate(mut options: BTreeMap<String, OsString>) -> CommandResult {
    let document_path = take_path(&mut options, "--operator-config", VALIDATE)?;
    finish_options(&options, VALIDATE)?;

    let bytes = read_bounded(
        &document_path,
        DOCUMENT_BYTES_MAX,
        VALIDATE,
        ErrorClass::CommandInput,
    )?;
    validate_document_bytes(&bytes, VALIDATE)?;

    Ok(format!(
        "{{\"command\":\"{VALIDATE}\",\"status\":\"VALIDATED_STATIC\"}}"
    ))
}

fn take_text_argument(
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<String, CommandError> {
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

fn take_path_argument(
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<PathBuf, CommandError> {
    arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| CommandError::input(PREPARE))
}

fn validate_document_bytes(bytes: &[u8], command: &'static str) -> Result<(), CommandError> {
    // Parsing accepts a path from its caller, but static validation never accesses it.
    let document = kapsel::parse_service_operator_document(
        bytes,
        PathBuf::from("/var/lib/kapsel/journal.sqlite3"),
    )
    .map_err(|_| CommandError::configuration(command))?;
    kapsel::ServiceApplication::validate_static_configuration(&document.configuration)
        .map_err(|_| CommandError::configuration(command))
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}")
            .unwrap_or_else(|_| unreachable!("writing to a String cannot fail"));
    }

    output
}
