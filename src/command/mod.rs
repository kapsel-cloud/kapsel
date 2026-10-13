//! Parses operator provisioning commands and offline receipt inspection commands.

mod service;

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
};

use kapsel::{
    inspect_receipt, provision_exact_grant, provision_snapshot_grant, ApplicationError,
    ExactAuthorization, GitObservedRef, GrantProvisioning, InspectionLimits, InspectionReport,
    InspectionStatus, OperationResult, ReceiptStatement,
};
use rustix::fs::{openat, Mode, OFlags, CWD};
use serde::Deserialize;
use tokio::runtime::Builder;

const JSON_BYTES_MAX: usize = 16 * 1024;
const MACHINE_OUTPUT_BYTES_MAX: usize = 64 * 1024;
const NON_CLAIMS: &str = concat!(
    "no-exactly-once;no-causation;no-kubernetes-truth;",
    "no-complete-capture;no-witnessing;not-production"
);

type CommandResult = Result<String, CommandError>;

pub(crate) fn run(arguments: impl Iterator<Item = OsString>) -> CommandResult {
    let mut arguments = arguments;
    let Some(subcommand) = arguments.next() else {
        return Err(CommandError::input("kapsel"));
    };
    let subcommand = subcommand
        .into_string()
        .map_err(|_| CommandError::input("kapsel"))?;
    match subcommand.as_str() {
        "--help" => help(arguments),
        "--version" => version(arguments),
        "prepare-service-config" => service::prepare(arguments),
        "validate-service-config" => {
            service::validate(parse_options("validate-service-config", arguments)?)
        },
        "provision-git-grant" => provision_git(parse_options("provision-git-grant", arguments)?),
        "provision-grant" => provision(parse_options("provision-grant", arguments)?, false),
        "provision-snapshot-grant" => {
            provision(parse_options("provision-snapshot-grant", arguments)?, true)
        },
        "inspect" => inspect(parse_options("inspect", arguments)?),
        _ => Err(CommandError::input("kapsel")),
    }
}

fn help(mut arguments: impl Iterator<Item = OsString>) -> CommandResult {
    if arguments.next().is_some() {
        return Err(CommandError::input("kapsel"));
    }
    Ok(concat!(
        "kapsel: controlled effects and offline receipt inspection\n",
        "Usage:\n",
        "  kapsel --help | --version\n",
        "  kapsel provision-grant --authorization <file> --signing-seed <file>\n",
        "    --signing-key-id <id> --output <new-file>\n",
        "  kapsel provision-snapshot-grant <same options> --kubeconfig <file>\n",
        "  kapsel provision-git-grant <same options> --git-receiver <file>\n",
        "  kapsel prepare-service-config [--authorization-key <id> <raw-public-key-file>]...\n",
        "    [--approval <label> <signed-grant-file>]...\n",
        "    --receipt-signing-key-id <id> --output <new-file>\n",
        "  kapsel validate-service-config --operator-config <file>\n",
        "  kapsel inspect --receipt <file> --trust <file> --evaluation-time-unix-s <i64>\n",
        "    [--receipt-bytes-max <usize>] [--statement-bytes-max <usize>]\n",
        "    [--trust-bytes-max <usize>] [--text-bytes-max <usize>]\n",
        "Execution uses kapseld and the fixed ID-only service client/MCP bridge.\n",
        "Service configuration validation is static, not execution readiness or publication.\n",
        "Exit 2: input, 3: configuration, 4: operation/output failure.\n",
        "Exit 0 alone does not establish a receiver outcome. Inspect the response."
    )
    .into())
}

fn version(mut arguments: impl Iterator<Item = OsString>) -> CommandResult {
    if arguments.next().is_some() {
        return Err(CommandError::input("kapsel"));
    }
    Ok(format!("kapsel {}", env!("CARGO_PKG_VERSION")))
}

fn parse_options(
    command: &'static str,
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<BTreeMap<String, OsString>, CommandError> {
    let mut options = BTreeMap::new();
    while let Some(option) = arguments.next() {
        let option = option
            .into_string()
            .map_err(|_| CommandError::input(command))?;
        if !option.starts_with("--") || option.len() == 2 || options.contains_key(&option) {
            return Err(CommandError::input(command));
        }
        let value = arguments
            .next()
            .ok_or_else(|| CommandError::input(command))?;
        if value.to_string_lossy().starts_with("--") {
            return Err(CommandError::input(command));
        }
        options.insert(option, value);
    }
    Ok(options)
}

fn take_path(
    options: &mut BTreeMap<String, OsString>,
    name: &str,
    command: &'static str,
) -> Result<PathBuf, CommandError> {
    options
        .remove(name)
        .map(PathBuf::from)
        .ok_or_else(|| CommandError::input(command))
}

fn take_text(
    options: &mut BTreeMap<String, OsString>,
    name: &str,
    command: &'static str,
) -> Result<String, CommandError> {
    options
        .remove(name)
        .ok_or_else(|| CommandError::input(command))?
        .into_string()
        .map_err(|_| CommandError::input(command))
}

fn finish_options(
    options: &BTreeMap<String, OsString>,
    command: &'static str,
) -> Result<(), CommandError> {
    if options.is_empty() {
        Ok(())
    } else {
        Err(CommandError::input(command))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationDocument {
    authorization_id: String,
    operation_id: String,
    namespace: String,
    deployment: String,
    container: String,
    immutable_image_digest: String,
}

fn provision(mut options: BTreeMap<String, OsString>, snapshot: bool) -> CommandResult {
    let command = if snapshot {
        "provision-snapshot-grant"
    } else {
        "provision-grant"
    };
    let kubeconfig = if snapshot {
        Some(take_path(&mut options, "--kubeconfig", command)?)
    } else {
        None
    };
    let authorization_path = take_path(&mut options, "--authorization", command)?;
    let seed_path = take_path(&mut options, "--signing-seed", command)?;
    let key_id = take_text(&mut options, "--signing-key-id", command)?;
    let output_path = take_path(&mut options, "--output", command)?;
    finish_options(&options, command)?;

    let document: AuthorizationDocument = read_json(&authorization_path, command)?;
    let seed = read_exact_32(&seed_path, command, ErrorClass::OperatorConfiguration)?;
    let authorization = ExactAuthorization {
        approved_target: None,
        authorization_id: document.authorization_id,
        operation_id: document.operation_id,
        namespace: document.namespace,
        deployment: document.deployment,
        container: document.container,
        immutable_image_digest: document.immutable_image_digest,
    };
    let provisioning = GrantProvisioning {
        authorization: &authorization,
        signing_seed: &seed,
        signing_key_id: &key_id,
    };
    let grant = if let Some(path) = kubeconfig {
        let bytes = read_bounded(
            &path,
            JSON_BYTES_MAX,
            command,
            ErrorClass::OperatorConfiguration,
        )?;
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| CommandError::configuration(command))?;
        runtime.block_on(provision_snapshot_grant(&provisioning, &bytes))
    } else {
        provision_exact_grant(&provisioning)
    }
    .map_err(|error| application_error_to_command(command, &error))?;

    publish_grant(command, &output_path, &grant)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GitAuthorizationDocument {
    operation_id: String,
    authorization_id: String,
    repository_id: String,
    reference: String,
    old_commit: String,
    new_commit: String,
}

fn provision_git(mut options: BTreeMap<String, OsString>) -> CommandResult {
    const COMMAND: &str = "provision-git-grant";
    let authorization_path = take_path(&mut options, "--authorization", COMMAND)?;
    let receiver_path = take_path(&mut options, "--git-receiver", COMMAND)?;
    let seed_path = take_path(&mut options, "--signing-seed", COMMAND)?;
    let key_id = take_text(&mut options, "--signing-key-id", COMMAND)?;
    let output_path = take_path(&mut options, "--output", COMMAND)?;
    finish_options(&options, COMMAND)?;

    let bytes = read_bounded(&authorization_path, 4096, COMMAND, ErrorClass::CommandInput)?;
    let document: GitAuthorizationDocument = decode_object(&bytes, COMMAND)?;
    let receiver_document = read_bounded(
        &receiver_path,
        4096,
        COMMAND,
        ErrorClass::OperatorConfiguration,
    )?;

    let receiver = kapsel::GitReceiverConfiguration::from_document(&receiver_document)
        .ok_or_else(|| CommandError::configuration(COMMAND))?;
    let seed = read_exact_32(&seed_path, COMMAND, ErrorClass::OperatorConfiguration)?;
    let authorization = kapsel_authority::GitRefAuthorization {
        operation_id: document.operation_id,
        authorization_id: document.authorization_id,
        repository_id: document.repository_id,
        reference: document.reference,
        old_commit: document.old_commit,
        new_commit: document.new_commit,
    };

    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| CommandError::configuration(COMMAND))?;
    let grant = runtime
        .block_on(kapsel::provision_git_ref_grant(
            &authorization,
            &receiver,
            &seed,
            &key_id,
        ))
        .map_err(|error| application_error_to_command(COMMAND, &error))?;

    publish_grant(COMMAND, &output_path, &grant)
}

fn publish_grant(command: &'static str, path: &Path, grant: &[u8]) -> CommandResult {
    write_new_private(path, grant).map_err(|_| CommandError::configuration(command))?;
    Ok(format!(
        "{{\"command\":\"{command}\",\"status\":\"PROVISIONED\"}}"
    ))
}

fn application_error_to_command(command: &'static str, error: &ApplicationError) -> CommandError {
    match error {
        ApplicationError::InvalidOperatorConfiguration | ApplicationError::InvalidJournalPath => {
            CommandError::configuration(command)
        },
        ApplicationError::InvalidGrantProvisioning => CommandError::input(command),
    }
}

fn inspect(mut options: BTreeMap<String, OsString>) -> CommandResult {
    let receipt_path = take_path(&mut options, "--receipt", "inspect")?;
    let trust_path = take_path(&mut options, "--trust", "inspect")?;
    let evaluation_time_unix_s = take_text(&mut options, "--evaluation-time-unix-s", "inspect")?
        .parse::<i64>()
        .map_err(|_| CommandError::input("inspect"))?;
    let defaults = InspectionLimits::default();
    let limits = InspectionLimits {
        receipt_bytes_max: take_limit(
            &mut options,
            "--receipt-bytes-max",
            defaults.receipt_bytes_max,
        )?,
        statement_bytes_max: take_limit(
            &mut options,
            "--statement-bytes-max",
            defaults.statement_bytes_max,
        )?,
        trust_bytes_max: take_limit(&mut options, "--trust-bytes-max", defaults.trust_bytes_max)?,
        text_bytes_max: take_limit(&mut options, "--text-bytes-max", defaults.text_bytes_max)?,
    };
    finish_options(&options, "inspect")?;

    if !inspection_limits_are_valid(limits, defaults) {
        return Err(CommandError::input("inspect"));
    }

    let receipt_file = open_within_limit(
        &receipt_path,
        limits.receipt_bytes_max,
        "inspect",
        ErrorClass::CommandInput,
    )?;
    let trust_file = open_within_limit(
        &trust_path,
        limits.trust_bytes_max,
        "inspect",
        ErrorClass::CommandInput,
    )?;
    let (Some(receipt_file), Some(trust_file)) = (receipt_file, trust_file) else {
        return Ok(structure_rejected_output());
    };
    let receipt = read_opened_bounded(
        receipt_file,
        limits.receipt_bytes_max,
        "inspect",
        ErrorClass::CommandInput,
    )?;
    let trust = read_opened_bounded(
        trust_file,
        limits.trust_bytes_max,
        "inspect",
        ErrorClass::CommandInput,
    )?;

    let output = if receipt.starts_with(b"KAPSEL-GIT-REF-RECEIPT-") {
        render_git_inspection(&kapsel::inspect_git_receipt(
            &receipt,
            &trust,
            evaluation_time_unix_s,
            limits,
        ))
    } else {
        render_inspection(&inspect_receipt(
            &receipt,
            &trust,
            evaluation_time_unix_s,
            limits,
        ))
    };

    let newline_terminated_bytes = output.len().checked_add(1);
    if newline_terminated_bytes.is_none_or(|length| length > MACHINE_OUTPUT_BYTES_MAX) {
        return Err(CommandError::operation("inspect"));
    }
    Ok(output)
}

fn inspection_limits_are_valid(limits: InspectionLimits, maximum: InspectionLimits) -> bool {
    limits.receipt_bytes_max > 0
        && limits.receipt_bytes_max <= maximum.receipt_bytes_max
        && limits.statement_bytes_max > 0
        && limits.statement_bytes_max <= maximum.statement_bytes_max
        && limits.trust_bytes_max > 0
        && limits.trust_bytes_max <= maximum.trust_bytes_max
        && limits.text_bytes_max > 0
        && limits.text_bytes_max <= maximum.text_bytes_max
}

fn take_limit(
    options: &mut BTreeMap<String, OsString>,
    name: &str,
    default: usize,
) -> Result<usize, CommandError> {
    options.remove(name).map_or(Ok(default), |value| {
        value
            .into_string()
            .map_err(|_| CommandError::input("inspect"))?
            .parse::<usize>()
            .map_err(|_| CommandError::input("inspect"))
    })
}

fn read_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    command: &'static str,
) -> Result<T, CommandError> {
    let bytes = read_bounded(path, JSON_BYTES_MAX, command, ErrorClass::CommandInput)?;
    decode_object(&bytes, command)
}

fn decode_object<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    command: &'static str,
) -> Result<T, CommandError> {
    // Derived struct decoding also accepts positional arrays.
    // Operator intent requires named fields.
    if bytes.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
        return Err(CommandError::input(command));
    }
    serde_json::from_slice(bytes).map_err(|_| CommandError::input(command))
}

fn read_exact_32(
    path: &Path,
    command: &'static str,
    class: ErrorClass,
) -> Result<[u8; 32], CommandError> {
    read_bounded(path, 32, command, class)?
        .try_into()
        .map_err(|_| CommandError { command, class })
}

fn open_regular(
    path: &Path,
    command: &'static str,
    class: ErrorClass,
) -> Result<File, CommandError> {
    let descriptor = openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| CommandError { command, class })?;
    let file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|_| CommandError { command, class })?;
    if !metadata.is_file() {
        return Err(CommandError { command, class });
    }
    Ok(file)
}

fn open_within_limit(
    path: &Path,
    maximum: usize,
    command: &'static str,
    class: ErrorClass,
) -> Result<Option<File>, CommandError> {
    if maximum == 0 {
        return Err(CommandError { command, class });
    }
    let file = open_regular(path, command, class)?;
    let length = file
        .metadata()
        .map_err(|_| CommandError { command, class })?
        .len();
    if usize::try_from(length).map_or(true, |length| length > maximum) {
        Ok(None)
    } else {
        Ok(Some(file))
    }
}

fn read_bounded(
    path: &Path,
    maximum: usize,
    command: &'static str,
    class: ErrorClass,
) -> Result<Vec<u8>, CommandError> {
    let file =
        open_within_limit(path, maximum, command, class)?.ok_or(CommandError { command, class })?;
    read_opened_bounded(file, maximum, command, class)
}

fn read_opened_bounded(
    file: File,
    maximum: usize,
    command: &'static str,
    class: ErrorClass,
) -> Result<Vec<u8>, CommandError> {
    let capacity = maximum
        .checked_add(1)
        .ok_or(CommandError { command, class })?;
    let mut bytes = Vec::with_capacity(capacity);
    let read_bytes_max = u64::try_from(capacity).map_err(|_| CommandError { command, class })?;
    file.take(read_bytes_max)
        .read_to_end(&mut bytes)
        .map_err(|_| CommandError { command, class })?;
    if bytes.len() > maximum {
        return Err(CommandError { command, class });
    }
    Ok(bytes)
}

fn write_new_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;

    let opened_metadata = file.metadata()?;
    let named_metadata = fs::symlink_metadata(path)?;
    if opened_metadata.dev() != named_metadata.dev()
        || opened_metadata.ino() != named_metadata.ino()
    {
        return Err(std::io::Error::other("output path identity changed"));
    }
    Ok(())
}

fn structure_rejected_output() -> String {
    render_inspection_fields("STRUCTURE_REJECTED", None)
}

fn render_git_inspection(report: &kapsel::GitInspectionReport) -> String {
    let Some(statement) = report.statement() else {
        return serde_json::json!({"command":"inspect", "effect":"git.transition_ref",
            "status":inspection_status(report.status()), "statement":null})
        .to_string();
    };
    let authorization = statement.authorization();
    let observed_ref = match statement.observed_ref() {
        GitObservedRef::Commit(oid) => serde_json::json!({"kind":"commit", "commit":oid}),
        GitObservedRef::Missing => serde_json::json!({"kind":"missing", "commit":null}),
        GitObservedRef::Unknown => serde_json::json!({"kind":"unknown", "commit":null}),
    };
    serde_json::json!({
        "command":"inspect", "effect":"git.transition_ref",
        "status":inspection_status(report.status()), "operation_id":authorization.operation_id,
        "authorization_id":authorization.authorization_id,
        "authorization_signer_key_id":statement.authorization_signer_key_id(),
        "authorization_grant_digest":statement.authorization_grant_digest(),
        "repository_id":authorization.repository_id, "reference":authorization.reference,
        "old_commit":authorization.old_commit, "new_commit":authorization.new_commit,
        "write_strategy":"git-exact-lease", "acknowledgement":statement.acknowledgement().as_str(),
        "observed_ref":observed_ref, "attribution":statement.attribution(),
        "result":operation_result(statement.result()),
        "non_claims":kapsel::GitReceiptStatement::non_claims(),
    })
    .to_string()
}

fn render_inspection(report: &InspectionReport) -> String {
    render_inspection_fields(inspection_status(report.status()), report.statement())
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixed classifier-complete machine record keeps field order explicit"
)]
fn render_inspection_fields(status: &str, statement: Option<&ReceiptStatement>) -> String {
    let mut output = format!("{{\"command\":\"inspect\",\"status\":\"{status}\"");
    let Some(statement) = statement else {
        for name in [
            "operation_id",
            "authorization_id",
            "authorization_signer_key_id",
            "authorization_grant_digest",
            "namespace",
            "deployment",
            "container",
            "immutable_image_digest",
            "write_strategy",
            "target_uid",
            "target_resource_version",
            "receiver_uid",
            "observed_image",
            "observed_operation_marker",
            "current_generation",
            "requested_generation",
            "observed_generation",
            "observed_resource_version",
            "desired_replicas",
            "updated_replicas",
            "available_replicas",
            "unavailable_replicas",
            "rollout_condition_type",
            "rollout_condition_status",
            "rollout_condition_reason",
            "result",
            "non_claims",
        ] {
            append_json_field(&mut output, name, "null");
        }
        output.push('}');
        return output;
    };

    let text_fields = [
        ("operation_id", Some(statement.operation_id())),
        ("authorization_id", Some(statement.authorization_id())),
        (
            "authorization_signer_key_id",
            Some(statement.authorization_signer_key_id()),
        ),
        (
            "authorization_grant_digest",
            Some(statement.authorization_grant_digest()),
        ),
        ("namespace", Some(statement.namespace())),
        ("deployment", Some(statement.deployment())),
        ("container", Some(statement.container())),
        (
            "immutable_image_digest",
            Some(statement.immutable_image_digest()),
        ),
        ("write_strategy", Some(statement.write_strategy())),
        ("target_uid", Some(statement.target_uid())),
        (
            "target_resource_version",
            Some(statement.target_resource_version()),
        ),
        ("receiver_uid", statement.receiver_uid()),
        ("observed_image", statement.observed_image()),
        (
            "observed_operation_marker",
            statement.observed_operation_marker(),
        ),
    ];
    for (name, value) in text_fields {
        append_json_field(&mut output, name, &optional_json(value));
    }

    for (name, value) in [
        ("current_generation", statement.current_generation()),
        ("requested_generation", statement.requested_generation()),
        ("observed_generation", statement.observed_generation()),
    ] {
        append_json_field(&mut output, name, &optional_number(value));
    }
    append_json_field(
        &mut output,
        "observed_resource_version",
        &optional_json(statement.observed_resource_version()),
    );

    for (name, value) in [
        ("desired_replicas", statement.desired_replicas()),
        ("updated_replicas", statement.updated_replicas()),
        ("available_replicas", statement.available_replicas()),
        ("unavailable_replicas", statement.unavailable_replicas()),
    ] {
        append_json_field(&mut output, name, &optional_number(value));
    }

    for (name, value) in [
        ("rollout_condition_type", statement.rollout_condition_type()),
        (
            "rollout_condition_status",
            statement.rollout_condition_status(),
        ),
        (
            "rollout_condition_reason",
            statement.rollout_condition_reason(),
        ),
    ] {
        append_json_field(&mut output, name, &optional_json(value));
    }

    append_json_field(
        &mut output,
        "result",
        &json_string(operation_result(statement.result())),
    );
    append_target_field(
        &mut output,
        "approved_target",
        statement.approved_target().map(|target| TargetProjection {
            uid: Some(target.uid.as_str()),
            resource_version: Some(target.resource_version.as_str()),
        }),
    );
    append_target_field(
        &mut output,
        "attempt_target",
        Some(TargetProjection {
            uid: Some(statement.target_uid()),
            resource_version: Some(statement.target_resource_version()),
        }),
    );
    append_target_field(
        &mut output,
        "observed_target",
        Some(TargetProjection {
            uid: statement.receiver_uid(),
            resource_version: statement.observed_resource_version(),
        }),
    );
    append_json_field(&mut output, "non_claims", &json_string(NON_CLAIMS));
    output.push('}');
    output
}

struct TargetProjection<'a> {
    uid: Option<&'a str>,
    resource_version: Option<&'a str>,
}

fn append_target_field(output: &mut String, name: &str, value: Option<TargetProjection<'_>>) {
    append_json_field(output, name, &target_field_json(value));
}

fn target_field_json(value: Option<TargetProjection<'_>>) -> String {
    value.map_or_else(
        || String::from("null"),
        |target| {
            format!(
                "{{\"resource_version\":{},\"uid\":{}}}",
                optional_json(target.resource_version),
                optional_json(target.uid)
            )
        },
    )
}

fn append_json_field(output: &mut String, name: &str, value: &str) {
    write!(output, ",\"{name}\":{value}")
        .unwrap_or_else(|_| unreachable!("writing into String cannot fail"));
}

fn optional_number<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| String::from("null"), |value| value.to_string())
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| unreachable!("serializing a string as JSON cannot fail"))
}

fn optional_json(value: Option<&str>) -> String {
    value.map_or_else(|| "null".into(), json_string)
}

const fn operation_result(value: OperationResult) -> &'static str {
    match value {
        OperationResult::Succeeded => "SUCCEEDED",
        OperationResult::Failed => "FAILED",
        OperationResult::Unknown => "UNKNOWN",
    }
}

const fn inspection_status(value: InspectionStatus) -> &'static str {
    match value {
        InspectionStatus::StructureRejected => "STRUCTURE_REJECTED",
        InspectionStatus::SignatureRejected => "SIGNATURE_REJECTED",
        InspectionStatus::UntrustedSigner => "UNTRUSTED_SIGNER",
        InspectionStatus::Inspected => "INSPECTED",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_scratch::Scratch;

    #[test]
    fn target_projection_matches_previous_json_shape_for_meaningful_targets() {
        for (projection, previous) in [
            (
                Some(TargetProjection {
                    uid: Some("approved-uid-\\\""),
                    resource_version: Some("approved-rv-\\\""),
                }),
                serde_json::json!({
                    "uid": "approved-uid-\\\"",
                    "resource_version": "approved-rv-\\\"",
                }),
            ),
            (
                Some(TargetProjection {
                    uid: None,
                    resource_version: Some("observed-rv"),
                }),
                serde_json::json!({"uid": null, "resource_version": "observed-rv"}),
            ),
            (
                Some(TargetProjection {
                    uid: Some("observed-uid"),
                    resource_version: None,
                }),
                serde_json::json!({"uid": "observed-uid", "resource_version": null}),
            ),
            (None, serde_json::Value::Null),
        ] {
            assert_eq!(target_field_json(projection), previous.to_string());
        }
    }

    #[test]
    fn authorization_objects_reject_ambiguous_shapes_before_material_access() {
        let valid = serde_json::json!({
            "authorization_id":"auth-1", "operation_id":"op-1", "namespace":"demo",
            "deployment":"agent-api", "container":"api",
            "immutable_image_digest":format!("registry.example/api@sha256:{}", "a".repeat(64)),
        });
        assert!(decode_object::<AuthorizationDocument>(
            &serde_json::to_vec(&valid).unwrap(),
            "provision-grant"
        )
        .is_ok());
        assert!(decode_object::<GitAuthorizationDocument>(
            br#"{
            "operation_id":"op-1", "authorization_id":"auth-1", "repository_id":"repo-1",
            "reference":"refs/heads/main", "old_commit":"a", "new_commit":"b"
        }"#,
            "provision-git-grant"
        )
        .is_ok());
        for hostile in [
            serde_json::json!(["auth-1", "op-1", "demo", "agent-api", "api", "image"]),
            serde_json::Value::Null,
            {
                let mut value = valid.clone();
                value["namespace"] = serde_json::json!(1);
                value
            },
            {
                let mut value = valid.clone();
                value["journal_path"] = serde_json::json!("SECRET");
                value
            },
            {
                let mut value = valid.clone();
                value.as_object_mut().unwrap().remove("operation_id");
                value
            },
        ] {
            assert!(decode_object::<AuthorizationDocument>(
                &serde_json::to_vec(&hostile).unwrap(),
                "provision-grant"
            )
            .is_err());
        }
        let text = serde_json::to_string(&valid).unwrap();
        for hostile in [
            text.replacen('{', "{\"operation_id\":\"duplicate\",", 1),
            text + " {}",
        ] {
            assert!(
                decode_object::<AuthorizationDocument>(hostile.as_bytes(), "provision-grant")
                    .is_err()
            );
        }
    }

    #[test]
    fn command_grammar_and_failure_records_are_fixed_before_io() {
        for arguments in [
            vec!["--x"],
            vec!["--x", "--y"],
            vec!["x", "value"],
            vec!["--x", "a", "--x", "b"],
            vec!["--", "value"],
        ] {
            assert!(parse_options("inspect", arguments.into_iter().map(OsString::from)).is_err());
        }
        for arguments in [
            vec![],
            vec!["operate", "--operator-config", "SECRET"],
            vec!["mcp"],
            vec!["--help", "SECRET"],
            vec!["--version", "SECRET"],
            vec!["provision-grant", "--extra", "SECRET"],
        ] {
            assert_eq!(
                run(arguments.into_iter().map(OsString::from))
                    .err()
                    .unwrap()
                    .exit_code(),
                2
            );
        }
        for (error, code, class) in [
            (CommandError::input("inspect"), 2, "command_input"),
            (
                CommandError::configuration("inspect"),
                3,
                "operator_configuration",
            ),
            (CommandError::operation("inspect"), 4, "operation_failure"),
        ] {
            assert_eq!(error.exit_code(), code);
            assert_eq!(
                error.machine_output(),
                format!(
                    "{{\"command\":\"inspect\",\"status\":\"ERROR\",\"error_class\":\"{class}\"}}"
                )
            );
            assert_eq!(
                error.diagnostic(),
                format!("Kapsel command failure: {class}")
            );
        }
        assert_eq!(
            run([OsString::from("--version")].into_iter()).ok().unwrap(),
            format!("kapsel {}", env!("CARGO_PKG_VERSION"))
        );
        let help = run([OsString::from("--help")].into_iter()).ok().unwrap();
        assert!(
            help.contains("prepare-service-config") && help.contains("validate-service-config")
        );
        assert!(help.contains("kapseld") && help.contains("kapsel inspect"));
        assert!(!help.contains("kapsel operate") && !help.contains("kapsel mcp --"));
    }

    #[test]
    fn snapshot_failures_keep_input_and_operator_material_distinct() {
        let root = Scratch::new();
        let valid = format!(
            r#"{{"authorization_id":"auth-1", "operation_id":"op-1",
            "namespace":"demo", "deployment":"agent-api", "container":"api",
            "immutable_image_digest":"registry.example/api@sha256:{}"}}"#,
            "a".repeat(64)
        );
        let options = BTreeMap::from([
            (
                "--authorization".into(),
                root.0.join("intent").into_os_string(),
            ),
            (
                "--signing-seed".into(),
                root.0.join("seed").into_os_string(),
            ),
            (
                "--kubeconfig".into(),
                root.0.join("kubeconfig").into_os_string(),
            ),
            ("--signing-key-id".into(), OsString::from("key-1")),
            ("--output".into(), root.0.join("grant").into_os_string()),
        ]);
        for (intent, seed, code, class) in [
            ("SECRET_INVALID_INTENT", vec![7; 32], 2, "command_input"),
            (valid.as_str(), vec![7; 31], 3, "operator_configuration"),
            (valid.as_str(), vec![7; 32], 3, "operator_configuration"),
        ] {
            fs::write(root.0.join("intent"), intent).unwrap();
            fs::write(root.0.join("seed"), seed).unwrap();
            fs::write(root.0.join("kubeconfig"), "SECRET: [invalid").unwrap();
            let error = provision(options.clone(), true).err().unwrap();
            assert_eq!(error.exit_code(), code);
            assert_eq!(
                error.machine_output(),
                format!(
                    concat!(
                        "{{\"command\":\"provision-snapshot-grant\",\"status\":\"ERROR\",",
                        "\"error_class\":\"{}\"}}",
                    ),
                    class
                )
            );
            assert!(!root.0.join("grant").exists());
        }
    }

    #[test]
    fn input_descriptors_are_regular_bounded_and_not_reopened_by_name() {
        let root = Scratch::new();
        let path = root.0.join("input");
        for length in [31, 32, 33] {
            fs::write(&path, vec![7; length]).unwrap();
            assert_eq!(
                read_exact_32(&path, "inspect", ErrorClass::CommandInput).is_ok(),
                length == 32
            );
        }
        fs::write(&path, b"original").unwrap();
        assert!(
            open_within_limit(&path, 7, "inspect", ErrorClass::CommandInput)
                .ok()
                .unwrap()
                .is_none()
        );
        let file = open_regular(&path, "inspect", ErrorClass::CommandInput)
            .ok()
            .unwrap();
        fs::rename(&path, root.0.join("old-input")).unwrap();
        fs::write(&path, b"replacement").unwrap();
        assert_eq!(
            read_opened_bounded(file, 8, "inspect", ErrorClass::CommandInput)
                .ok()
                .unwrap(),
            b"original"
        );
        let file = open_regular(&path, "inspect", ErrorClass::CommandInput)
            .ok()
            .unwrap();
        fs::write(&path, b"grown beyond the original bound").unwrap();
        assert!(read_opened_bounded(file, 11, "inspect", ErrorClass::CommandInput).is_err());
        std::os::unix::fs::symlink(&path, root.0.join("link")).unwrap();
        assert!(std::process::Command::new("mkfifo")
            .arg(root.0.join("fifo"))
            .status()
            .unwrap()
            .success());
        for path in [
            root.0.clone(),
            root.0.join("missing"),
            root.0.join("link"),
            root.0.join("fifo"),
        ] {
            assert!(open_regular(&path, "inspect", ErrorClass::CommandInput).is_err());
        }
    }

    #[test]
    fn new_output_is_private_and_existing_files_or_links_cannot_be_replaced() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = Scratch::new();
        let output = root.0.join("output");
        assert_eq!(
            publish_grant("provision-grant", &output, b"original")
                .ok()
                .unwrap(),
            "{\"command\":\"provision-grant\",\"status\":\"PROVISIONED\"}"
        );
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::os::unix::fs::symlink(&output, root.0.join("link")).unwrap();
        for command in [
            "provision-grant",
            "provision-snapshot-grant",
            "provision-git-grant",
        ] {
            for path in [&output, &root.0.join("link")] {
                let error = publish_grant(command, path, b"replacement").err().unwrap();
                assert_eq!(error.exit_code(), 3);
                assert_eq!(
                    error.machine_output(),
                    format!(
                        concat!(
                            "{{\"command\":\"{}\",\"status\":\"ERROR\",",
                            "\"error_class\":\"operator_configuration\"}}",
                        ),
                        command
                    )
                );
            }
        }
        assert_eq!(fs::read(&output).unwrap(), b"original");
    }

    #[test]
    fn inspection_dispatch_binds_lower_limits_and_untrusted_authenticated_facts() {
        let root = Scratch::new();
        let decode = |text: &str| {
            text.trim()
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect::<Vec<_>>()
        };
        fs::write(
            root.0.join("receipt"),
            decode(include_str!("../../vectors/effect-gateway-receipt.hex")),
        )
        .unwrap();
        fs::write(
            root.0.join("trust"),
            decode(include_str!("../../vectors/effect-gateway-trust.hex")),
        )
        .unwrap();
        let options = BTreeMap::from([
            ("--receipt".into(), root.0.join("receipt").into_os_string()),
            ("--trust".into(), root.0.join("trust").into_os_string()),
            ("--evaluation-time-unix-s".into(), OsString::from("150")),
        ]);
        let baseline: serde_json::Value =
            serde_json::from_str(&inspect(options.clone()).ok().unwrap()).unwrap();
        assert_eq!(baseline["status"], "INSPECTED");
        let mut limited = options.clone();
        limited.insert("--statement-bytes-max".into(), OsString::from("1"));
        let record: serde_json::Value =
            serde_json::from_str(&inspect(limited).ok().unwrap()).unwrap();
        assert_eq!(record["status"], "STRUCTURE_REJECTED");
        assert!(record["operation_id"].is_null());
        fs::write(
            root.0.join("trust"),
            kapsel::ReceiptTrust {
                key_id: "different-key".into(),
                public_key: ed25519_dalek::SigningKey::from_bytes(&[9; 32])
                    .verifying_key()
                    .to_bytes(),
                accepted_purpose: "kapsel.kap0038.kubernetes-effect-receipt.v2".into(),
                not_before_unix_s: 100,
                not_after_unix_s: 200,
            }
            .encode()
            .unwrap(),
        )
        .unwrap();
        let record: serde_json::Value =
            serde_json::from_str(&inspect(options).ok().unwrap()).unwrap();
        let mut expected = baseline;
        expected["status"] = serde_json::json!("UNTRUSTED_SIGNER");
        assert_eq!(record, expected);
    }

    #[test]
    fn inspection_status_and_limit_partitions_do_not_appoint_trust_or_expand_bounds() {
        for (status, expected) in [
            (InspectionStatus::StructureRejected, "STRUCTURE_REJECTED"),
            (InspectionStatus::SignatureRejected, "SIGNATURE_REJECTED"),
            (InspectionStatus::UntrustedSigner, "UNTRUSTED_SIGNER"),
            (InspectionStatus::Inspected, "INSPECTED"),
        ] {
            assert_eq!(inspection_status(status), expected);
        }
        let maximum = InspectionLimits::default();
        let maxima = [
            maximum.receipt_bytes_max,
            maximum.statement_bytes_max,
            maximum.trust_bytes_max,
            maximum.text_bytes_max,
        ];
        for field in 0..4 {
            for value in [0, 1, maxima[field], maxima[field] + 1] {
                let mut values = maxima;
                values[field] = value;
                let limits = InspectionLimits {
                    receipt_bytes_max: values[0],
                    statement_bytes_max: values[1],
                    trust_bytes_max: values[2],
                    text_bytes_max: values[3],
                };
                assert_eq!(
                    inspection_limits_are_valid(limits, maximum),
                    value > 0 && value <= maxima[field]
                );
            }
        }
        let output: serde_json::Value = serde_json::from_str(&structure_rejected_output()).unwrap();
        assert_eq!(output["status"], "STRUCTURE_REJECTED");
        assert!(output["operation_id"].is_null() && output["non_claims"].is_null());
    }
}

#[derive(Clone, Copy)]
enum ErrorClass {
    CommandInput,
    OperatorConfiguration,
    OperationFailure,
}

pub(crate) struct CommandError {
    command: &'static str,
    class: ErrorClass,
}

impl CommandError {
    const fn input(command: &'static str) -> Self {
        Self {
            command,
            class: ErrorClass::CommandInput,
        }
    }

    const fn configuration(command: &'static str) -> Self {
        Self {
            command,
            class: ErrorClass::OperatorConfiguration,
        }
    }

    const fn operation(command: &'static str) -> Self {
        Self {
            command,
            class: ErrorClass::OperationFailure,
        }
    }

    const fn class_name(&self) -> &'static str {
        match self.class {
            ErrorClass::CommandInput => "command_input",
            ErrorClass::OperatorConfiguration => "operator_configuration",
            ErrorClass::OperationFailure => "operation_failure",
        }
    }

    pub(crate) fn exit_code(&self) -> u8 {
        match self.class {
            ErrorClass::CommandInput => 2,
            ErrorClass::OperatorConfiguration => 3,
            ErrorClass::OperationFailure => 4,
        }
    }

    pub(crate) fn machine_output(&self) -> String {
        format!(
            "{{\"command\":\"{}\",\"status\":\"ERROR\",\"error_class\":\"{}\"}}",
            self.command,
            self.class_name()
        )
    }

    pub(crate) fn diagnostic(&self) -> String {
        format!("Kapsel command failure: {}", self.class_name())
    }
}
