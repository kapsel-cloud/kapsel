//! Fixed parser and composition for the KAP-0041 evaluator commands.

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
};

use kapsel::{
    inspect_receipt, provision_exact_grant, AgentRequest, Application, ApplicationError,
    AuthorizationTrust, ExactAuthorization, GatewayError, GrantProvisioning, InspectionLimits,
    InspectionReport, InspectionStatus, OperationReport, OperationResult, OperationState,
    OperatorConfiguration, TargetRejection,
};
use kube::{config::KubeConfigOptions, Config};
use rustix::fs::{openat, Mode, OFlags, CWD};
use serde::Deserialize;

const JSON_BYTES_MAX: usize = 16 * 1024;
const GRANT_BYTES_MAX: usize = 4 * 1024;
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
        "provision-grant" => provision(parse_options("provision-grant", arguments)?),
        "operate" => operate(parse_options("operate", arguments)?),
        "inspect" => inspect(parse_options("inspect", arguments)?),
        _ => Err(CommandError::input("kapsel")),
    }
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestDocument {
    operation_id: String,
    namespace: String,
    deployment: String,
    container: String,
    immutable_image_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorDocument {
    signed_authorization_grant: PathBuf,
    authorization_key_id: String,
    authorization_public_key: PathBuf,
    kubeconfig: PathBuf,
    journal: PathBuf,
    receipt_directory: PathBuf,
    receipt_signing_seed: PathBuf,
    receipt_signing_key_id: String,
}

fn provision(mut options: BTreeMap<String, OsString>) -> CommandResult {
    let authorization_path = take_path(&mut options, "--authorization", "provision-grant")?;
    let seed_path = take_path(&mut options, "--signing-seed", "provision-grant")?;
    let key_id = take_text(&mut options, "--signing-key-id", "provision-grant")?;
    let output_path = take_path(&mut options, "--output", "provision-grant")?;
    finish_options(&options, "provision-grant")?;

    let document: AuthorizationDocument = read_json(&authorization_path, "provision-grant")?;
    let seed = read_exact_32(
        &seed_path,
        "provision-grant",
        ErrorClass::OperatorConfiguration,
    )?;
    let authorization = ExactAuthorization {
        authorization_id: document.authorization_id,
        operation_id: document.operation_id,
        namespace: document.namespace,
        deployment: document.deployment,
        container: document.container,
        immutable_image_digest: document.immutable_image_digest,
    };
    let grant = provision_exact_grant(&GrantProvisioning {
        authorization: &authorization,
        signing_seed: &seed,
        signing_key_id: &key_id,
    })
    .map_err(|_| CommandError::input("provision-grant"))?;
    write_new_private(&output_path, &grant)
        .map_err(|_| CommandError::configuration("provision-grant"))?;
    Ok(r#"{"command":"provision-grant","status":"PROVISIONED"}"#.into())
}

fn operate(mut options: BTreeMap<String, OsString>) -> CommandResult {
    let request_path = take_path(&mut options, "--request", "operate")?;
    let operator_path = take_path(&mut options, "--operator-config", "operate")?;
    finish_options(&options, "operate")?;
    let request: RequestDocument = read_json(&request_path, "operate")?;
    let request = AgentRequest {
        operation_id: request.operation_id,
        namespace: request.namespace,
        deployment: request.deployment,
        container: request.container,
        immutable_image_digest: request.immutable_image_digest,
    };
    let operator: OperatorDocument =
        read_json_classified(&operator_path, "operate", ErrorClass::OperatorConfiguration)?;
    let runtime = runtime()?;
    let report = runtime.block_on(async {
        let configuration = load_operator_configuration(operator).await?;
        let mut application =
            Application::open(configuration).map_err(|error| map_application_open(&error))?;
        application
            .execute(&request)
            .await
            .map_err(|error| map_application_operation(&error))
    })?;
    render_operation(&report)
}

async fn load_operator_configuration(
    operator: OperatorDocument,
) -> Result<OperatorConfiguration, CommandError> {
    for path in [
        &operator.signed_authorization_grant,
        &operator.authorization_public_key,
        &operator.kubeconfig,
        &operator.journal,
        &operator.receipt_directory,
        &operator.receipt_signing_seed,
    ] {
        if !path.is_absolute() {
            return Err(CommandError::configuration("operate"));
        }
    }
    let grant = read_bounded(
        &operator.signed_authorization_grant,
        GRANT_BYTES_MAX,
        "operate",
        ErrorClass::OperatorConfiguration,
    )?;
    let authorization_public_key = read_exact_32(
        &operator.authorization_public_key,
        "operate",
        ErrorClass::OperatorConfiguration,
    )?;
    let receipt_seed = read_exact_32(
        &operator.receipt_signing_seed,
        "operate",
        ErrorClass::OperatorConfiguration,
    )?;
    let kubeconfig_bytes = read_bounded(
        &operator.kubeconfig,
        JSON_BYTES_MAX,
        "operate",
        ErrorClass::OperatorConfiguration,
    )?;
    let kubeconfig_text = std::str::from_utf8(&kubeconfig_bytes)
        .map_err(|_| CommandError::configuration("operate"))?;
    let mut kubeconfig = kube::config::Kubeconfig::from_yaml(kubeconfig_text)
        .map_err(|_| CommandError::configuration("operate"))?;
    let remove_proxy = suppress_ambient_proxy(&mut kubeconfig)?;
    let mut client_config =
        Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
            .await
            .map_err(|_| CommandError::configuration("operate"))?;
    if remove_proxy {
        client_config.proxy_url = None;
    }
    let kubernetes_client = kube::Client::try_from(client_config)
        .map_err(|_| CommandError::configuration("operate"))?;
    Ok(OperatorConfiguration {
        journal_path: operator.journal,
        receipt_output_directory: operator.receipt_directory,
        authorization_trust: AuthorizationTrust {
            key_id: operator.authorization_key_id,
            public_key: authorization_public_key,
        },
        signed_authorization_grant: grant,
        kubernetes_client,
        receipt_signing_seed: receipt_seed,
        receipt_signing_key_id: operator.receipt_signing_key_id,
    })
}

fn inspect(mut options: BTreeMap<String, OsString>) -> CommandResult {
    let receipt_path = take_path(&mut options, "--receipt", "inspect")?;
    let trust_path = take_path(&mut options, "--trust", "inspect")?;
    let evaluation_time = take_text(&mut options, "--evaluation-time-unix-s", "inspect")?
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
    if limits.receipt_bytes_max == 0
        || limits.receipt_bytes_max > defaults.receipt_bytes_max
        || limits.statement_bytes_max == 0
        || limits.statement_bytes_max > defaults.statement_bytes_max
        || limits.trust_bytes_max == 0
        || limits.trust_bytes_max > defaults.trust_bytes_max
        || limits.text_bytes_max == 0
        || limits.text_bytes_max > defaults.text_bytes_max
    {
        return Err(CommandError::input("inspect"));
    }
    if file_exceeds(&receipt_path, limits.receipt_bytes_max)?
        || file_exceeds(&trust_path, limits.trust_bytes_max)?
    {
        return Ok(structure_rejected_output());
    }
    let receipt = read_bounded(
        &receipt_path,
        limits.receipt_bytes_max,
        "inspect",
        ErrorClass::CommandInput,
    )?;
    let trust = read_bounded(
        &trust_path,
        limits.trust_bytes_max,
        "inspect",
        ErrorClass::CommandInput,
    )?;
    Ok(render_inspection(&inspect_receipt(
        &receipt,
        &trust,
        evaluation_time,
        limits,
    )))
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
    read_json_classified(path, command, ErrorClass::CommandInput)
}

fn read_json_classified<T: for<'de> Deserialize<'de>>(
    path: &Path,
    command: &'static str,
    class: ErrorClass,
) -> Result<T, CommandError> {
    let bytes = read_bounded(path, JSON_BYTES_MAX, command, class)?;
    serde_json::from_slice(&bytes).map_err(|_| CommandError { command, class })
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

fn suppress_ambient_proxy(kubeconfig: &mut kube::config::Kubeconfig) -> Result<bool, CommandError> {
    let current = kubeconfig
        .current_context
        .as_deref()
        .ok_or_else(|| CommandError::configuration("operate"))?;
    let context = kubeconfig
        .contexts
        .iter()
        .find(|context| context.name == current)
        .and_then(|context| context.context.as_ref())
        .ok_or_else(|| CommandError::configuration("operate"))?;
    let cluster_name = context.cluster.clone();
    let user_name = context.user.clone();
    let cluster = kubeconfig
        .clusters
        .iter_mut()
        .find(|cluster| cluster.name == cluster_name)
        .and_then(|cluster| cluster.cluster.as_mut())
        .ok_or_else(|| CommandError::configuration("operate"))?;
    if cluster.certificate_authority.is_some() {
        return Err(CommandError::configuration("operate"));
    }
    if let Some(user_name) = user_name {
        let user = kubeconfig
            .auth_infos
            .iter()
            .find(|user| user.name == user_name)
            .and_then(|user| user.auth_info.as_ref())
            .ok_or_else(|| CommandError::configuration("operate"))?;
        if user.token_file.is_some()
            || user.client_certificate.is_some()
            || user.client_key.is_some()
            || user.auth_provider.is_some()
            || user.exec.is_some()
        {
            return Err(CommandError::configuration("operate"));
        }
    }
    if cluster.proxy_url.as_deref().is_none_or(str::is_empty) {
        cluster.proxy_url = Some(String::from("http://127.0.0.1"));
        Ok(true)
    } else {
        Ok(false)
    }
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
    if !file
        .metadata()
        .map_err(|_| CommandError { command, class })?
        .is_file()
    {
        return Err(CommandError { command, class });
    }
    Ok(file)
}

fn file_exceeds(path: &Path, maximum: usize) -> Result<bool, CommandError> {
    let file = open_regular(path, "inspect", ErrorClass::CommandInput)?;
    let length = file
        .metadata()
        .map_err(|_| CommandError::input("inspect"))?
        .len();
    Ok(usize::try_from(length).map_or(true, |length| length > maximum))
}

fn read_bounded(
    path: &Path,
    maximum: usize,
    command: &'static str,
    class: ErrorClass,
) -> Result<Vec<u8>, CommandError> {
    if maximum == 0 {
        return Err(CommandError { command, class });
    }
    let file = open_regular(path, command, class)?;
    let metadata = file
        .metadata()
        .map_err(|_| CommandError { command, class })?;
    if usize::try_from(metadata.len()).map_or(true, |length| length > maximum) {
        return Err(CommandError { command, class });
    }
    let capacity = maximum
        .checked_add(1)
        .ok_or(CommandError { command, class })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(u64::try_from(capacity).map_err(|_| CommandError { command, class })?)
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
    let descriptor = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if descriptor.dev() != named.dev() || descriptor.ino() != named.ino() {
        return Err(std::io::Error::other("output path identity changed"));
    }
    Ok(())
}

fn runtime() -> Result<tokio::runtime::Runtime, CommandError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| CommandError::operation("operate"))
}

fn render_operation(report: &OperationReport) -> CommandResult {
    let operation_id = json_string(&report.operation_id);
    let state = operation_state(report.state);
    let result = optional_json(report.result.map(operation_result));
    let rejection = optional_json(report.target_rejection.map(target_rejection));
    let (receipt_file, receipt_digest) = if let Some(receipt) = &report.receipt {
        let file = receipt
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| CommandError::operation("operate"))?;
        (json_string(file), json_string(&receipt.digest))
    } else {
        ("null".into(), "null".into())
    };
    Ok(format!(
        concat!(
            "{{\"command\":\"operate\",\"operation_id\":{operation_id},",
            "\"state\":\"{state}\",\"result\":{result},",
            "\"target_rejection\":{rejection},\"receipt_file\":{receipt_file},",
            "\"receipt_sha256\":{receipt_digest}}}"
        ),
        operation_id = operation_id,
        state = state,
        result = result,
        rejection = rejection,
        receipt_file = receipt_file,
        receipt_digest = receipt_digest
    ))
}

fn structure_rejected_output() -> String {
    String::from(concat!(
        "{\"command\":\"inspect\",\"status\":\"STRUCTURE_REJECTED\",",
        "\"operation_id\":null,\"result\":null,\"non_claims\":null}"
    ))
}

fn render_inspection(report: &InspectionReport) -> String {
    let status = inspection_status(report.status());
    let (operation_id, result, non_claims) = report.statement().map_or_else(
        || ("null".into(), "null".into(), "null".into()),
        |statement| {
            (
                json_string(statement.operation_id()),
                json_string(operation_result(statement.result())),
                json_string(NON_CLAIMS),
            )
        },
    );
    format!(
        concat!(
            "{{\"command\":\"inspect\",\"status\":\"{status}\",",
            "\"operation_id\":{operation_id},\"result\":{result},",
            "\"non_claims\":{non_claims}}}"
        ),
        status = status,
        operation_id = operation_id,
        result = result,
        non_claims = non_claims
    )
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| String::from("null"))
}

fn optional_json(value: Option<&str>) -> String {
    value.map_or_else(|| "null".into(), json_string)
}

const fn operation_state(value: OperationState) -> &'static str {
    match value {
        OperationState::Requested => "REQUESTED",
        OperationState::Authorized => "AUTHORIZED",
        OperationState::NotAttempted => "NOT_ATTEMPTED",
        OperationState::ApplyStarted => "APPLY_STARTED",
        OperationState::ReceiverObserved => "RECEIVER_OBSERVED",
        OperationState::ReceiptPrepared => "RECEIPT_PREPARED",
        OperationState::ReceiptWritten => "RECEIPT_WRITTEN",
        OperationState::Finalized => "FINALIZED",
    }
}

const fn operation_result(value: OperationResult) -> &'static str {
    match value {
        OperationResult::Succeeded => "SUCCEEDED",
        OperationResult::Failed => "FAILED",
        OperationResult::Unknown => "UNKNOWN",
    }
}

const fn target_rejection(value: TargetRejection) -> &'static str {
    match value {
        TargetRejection::DeploymentNotFound => "DEPLOYMENT_NOT_FOUND",
        TargetRejection::ContainerNotFound => "CONTAINER_NOT_FOUND",
        TargetRejection::InvalidTarget => "INVALID_TARGET",
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

fn map_application_open(error: &ApplicationError) -> CommandError {
    match error {
        ApplicationError::InvalidAuthorizationConfiguration
        | ApplicationError::InvalidReceiptConfiguration
        | ApplicationError::InvalidJournalPath
        | ApplicationError::InvalidReceiptOutputDirectory
        | ApplicationError::InvalidGrantProvisioning => CommandError::configuration("operate"),
        ApplicationError::Gateway(_) | ApplicationError::InvalidApplicationState => {
            CommandError::operation("operate")
        },
    }
}

fn map_application_operation(error: &ApplicationError) -> CommandError {
    match error {
        ApplicationError::Gateway(
            GatewayError::InvalidInput(_) | GatewayError::AuthorizationMismatch,
        ) => CommandError::input("operate"),
        _ => CommandError::operation("operate"),
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
