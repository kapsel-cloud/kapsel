//! Fixed-purpose one-shot key and channel staging roles.

use std::{
    collections::BTreeMap,
    env,
    fmt::Write as _,
    fs,
    io::{Cursor, Read},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use ed25519_dalek::SigningKey;
use kapsel::{provision_exact_grant, ExactAuthorization, GrantProvisioning};
use kube::{
    api::{Api, DynamicObject, PostParams},
    core::{ApiResource, GroupVersionKind},
    Client,
};
use rustls::{
    pki_types::{
        pem::{PemObject, SectionKind},
        CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
        ServerName,
    },
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::time::timeout;
use x509_parser::{extensions::GeneralName, parse_x509_certificate};
use zeroize::{Zeroize, Zeroizing};

use crate::runner_process::open_projected_or_regular;

const SYSTEM_NAMESPACE: &str = "kapsel-sandbox-system";
const RUNNER_NAMESPACE: &str = "kapsel-sandbox-runners";
const SERVER_DNS_NAME: &str = "kapsel-sandbox-controller-state.kapsel-sandbox-system.svc";
const FIELD_MANAGER: &str = "kapsel-fixed-stager";
const FILE_BYTES_MAX: usize = 16 * 1024;
const REQUEST_BYTES_MAX: usize = 8 * 1024;
const API_DEADLINE: Duration = Duration::from_secs(5);
const HEALTHY_IMAGE: &str = concat!(
    "registry.k8s.io/pause@sha256:",
    "8b5ea5e3a4c8c5c1d3112ca9a6df8ca4db74822e0e4d7109b1e7d1490c62058c"
);
const UNAVAILABLE_IMAGE: &str = concat!(
    "registry.k8s.io/pause@sha256:",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
);

#[derive(Clone, Copy, Eq, PartialEq)]
enum Role {
    ControllerTls,
    Tombstone,
    AuthorizationGrant,
    ReceiptSigning,
}

struct Arguments {
    role: Role,
    source_mount: PathBuf,
    request: Option<PathBuf>,
    key_identity: Option<PathBuf>,
    run_id: Option<String>,
    ca_sha256: Option<[u8; 32]>,
    ca_root_count: Option<u8>,
    kubernetes_ca: PathBuf,
    kubernetes_token: PathBuf,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum InputKind {
    Seed,
    Request,
    KeyIdentity,
    TlsCa,
    TlsCertificate,
    TlsPrivateKey,
    KubernetesCa,
    KubernetesToken,
}

struct OpenedInput {
    kind: InputKind,
    file: fs::File,
    metadata: fs::Metadata,
    maximum: usize,
}

struct LoadedInputs {
    seed: Option<Zeroizing<[u8; 32]>>,
    request: Option<Zeroizing<Vec<u8>>>,
    key_identity: Option<Zeroizing<Vec<u8>>>,
    tls_ca: Option<Zeroizing<Vec<u8>>>,
    tls_certificate: Option<Zeroizing<Vec<u8>>>,
    tls_private_key: Option<Zeroizing<Vec<u8>>>,
    kubernetes_ca: Zeroizing<Vec<u8>>,
    kubernetes_token: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ObservedObject {
    kind: String,
    namespace: String,
    name: String,
    uid: String,
    owner_label: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestDocument {
    operation_id: String,
    namespace: String,
    deployment: String,
    container: String,
    immutable_image_digest: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct KeyIdentityDocument {
    key_id: String,
    public_key_hex: String,
}

#[derive(Serialize)]
struct ResultEnvelope {
    protocol: &'static str,
    objects: Vec<ObservedObject>,
}

/// Runs one of the four fixed native staging roles.
///
/// # Errors
///
/// Returns only bounded role-independent diagnostics without source or Kubernetes response data.
pub fn run(
    command: &str,
    arguments: impl Iterator<Item = String>,
) -> Result<Option<String>, &'static str> {
    let arguments = Arguments::parse(command, arguments)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| "stager runtime is unavailable")?;
    runtime.block_on(async move {
        let loaded = load_inputs(&arguments)?;
        let client = projected_client(&loaded.kubernetes_ca, &loaded.kubernetes_token)?;
        let observations = match arguments.role {
            Role::ControllerTls => {
                stage_controller_tls(&arguments, &loaded, &client).await?;
                None
            },
            Role::Tombstone => {
                stage_tombstone(&loaded, &client).await?;
                None
            },
            Role::AuthorizationGrant => {
                Some(stage_authorization_grant(&arguments, &loaded, &client).await?)
            },
            Role::ReceiptSigning => Some(vec![
                stage_receipt_signing(&arguments, &loaded, &client).await?,
            ]),
        };
        observations.map(encode_result).transpose()
    })
}

fn encode_result(objects: Vec<ObservedObject>) -> Result<String, &'static str> {
    serde_json::to_string(&ResultEnvelope {
        protocol: "key-staging-result-v1",
        objects,
    })
    .map_err(|_| "stager result is unavailable")
}

impl Arguments {
    fn parse(command: &str, mut input: impl Iterator<Item = String>) -> Result<Self, &'static str> {
        let role = match command {
            "stage-controller-tls" => Role::ControllerTls,
            "stage-tombstone-key" => Role::Tombstone,
            "stage-authorization-grant" => Role::AuthorizationGrant,
            "stage-receipt-signing" => Role::ReceiptSigning,
            _ => return Err("stager arguments are invalid"),
        };
        let mut source_mount = None;
        let mut request = None;
        let mut key_identity = None;
        let mut run_id = None;
        let mut ca_sha256 = None;
        let mut ca_root_count = None;
        let mut kubernetes_ca = None;
        let mut kubernetes_token = None;
        while let Some(flag) = input.next() {
            let value = input.next().ok_or("stager arguments are invalid")?;
            match flag.as_str() {
                "--source-mount" if source_mount.is_none() => source_mount = Some(absolute(value)?),
                "--request" if request.is_none() => request = Some(absolute(value)?),
                "--key-identity" if key_identity.is_none() => {
                    key_identity = Some(absolute(value)?);
                },
                "--run-id" if run_id.is_none() => run_id = Some(valid_run_id(value)?),
                "--ca-sha256" if ca_sha256.is_none() => {
                    ca_sha256 = Some(parse_sha256(&value)?);
                },
                "--ca-root-count" if ca_root_count.is_none() => {
                    ca_root_count =
                        Some(value.parse().map_err(|_| "stager arguments are invalid")?);
                },
                "--kubernetes-ca" if kubernetes_ca.is_none() => {
                    kubernetes_ca = Some(absolute(value)?);
                },
                "--kubernetes-token" if kubernetes_token.is_none() => {
                    kubernetes_token = Some(absolute(value)?);
                },
                _ => return Err("stager arguments are invalid"),
            }
        }
        let per_run = matches!(role, Role::AuthorizationGrant | Role::ReceiptSigning);
        if source_mount.is_none()
            || kubernetes_ca.is_none()
            || kubernetes_token.is_none()
            || per_run != run_id.is_some()
            || per_run != key_identity.is_some()
            || (role == Role::AuthorizationGrant) != request.is_some()
            || (role == Role::ControllerTls) != ca_sha256.is_some()
            || (role == Role::ControllerTls) != ca_root_count.is_some()
            || ca_root_count.is_some_and(|count| !(1..=2).contains(&count))
        {
            return Err("stager arguments are invalid");
        }
        let source_mount = source_mount.ok_or("stager arguments are invalid")?;
        if request
            .as_ref()
            .is_some_and(|path| path.file_name() != Some(std::ffi::OsStr::new("request.json")))
            || key_identity.as_ref().is_some_and(|path| {
                path.file_name() != Some(std::ffi::OsStr::new("key-identity.json"))
            })
        {
            return Err("stager arguments are invalid");
        }
        Ok(Self {
            role,
            source_mount,
            request,
            key_identity,
            run_id,
            ca_sha256,
            ca_root_count,
            kubernetes_ca: kubernetes_ca.ok_or("stager arguments are invalid")?,
            kubernetes_token: kubernetes_token.ok_or("stager arguments are invalid")?,
        })
    }
}

async fn stage_tombstone(inputs: &LoadedInputs, client: &Client) -> Result<(), &'static str> {
    let seed = inputs.seed.as_ref().ok_or("stager source is invalid")?;
    let body = secret(
        SYSTEM_NAMESPACE,
        "kapsel-gate2-tombstone-digest",
        system_labels("tombstone"),
        [("tombstone-digest.seed", seed.as_slice())],
    );
    create_or_observe(client, &body).await?;
    Ok(())
}

async fn stage_receipt_signing(
    arguments: &Arguments,
    inputs: &LoadedInputs,
    client: &Client,
) -> Result<ObservedObject, &'static str> {
    let run_id = arguments
        .run_id
        .as_deref()
        .ok_or("stager arguments are invalid")?;
    let seed = inputs.seed.as_ref().ok_or("stager source is invalid")?;
    let identity = read_key_identity(inputs)?;
    require_seed_identity(seed, &identity)?;
    let body = secret(
        RUNNER_NAMESPACE,
        &format!("runner-receipt-signing-{run_id}"),
        run_labels(run_id, "receipt-signing"),
        [
            ("seed", seed.as_slice()),
            ("key-id", identity.key_id.as_bytes()),
        ],
    );
    let observed = create_or_observe(client, &body).await?;
    require_cleanup_owner(&observed, run_id)?;
    Ok(observed)
}

async fn stage_authorization_grant(
    arguments: &Arguments,
    inputs: &LoadedInputs,
    client: &Client,
) -> Result<Vec<ObservedObject>, &'static str> {
    let run_id = arguments
        .run_id
        .as_deref()
        .ok_or("stager arguments are invalid")?;
    let seed = inputs.seed.as_ref().ok_or("stager source is invalid")?;
    let identity = read_key_identity(inputs)?;
    require_seed_identity(seed, &identity)?;
    let key_id = identity.key_id.clone();
    let request_bytes = inputs
        .request
        .as_ref()
        .ok_or("stager arguments are invalid")?;
    let request: RequestDocument = serde_json::from_slice(request_bytes)
        .map_err(|_| "authorization staging input is invalid")?;
    if serde_json::to_vec(&request).map_err(|_| "authorization staging input is invalid")?
        != **request_bytes
    {
        return Err("authorization staging input is invalid");
    }
    validate_request(run_id, &request)?;
    let authorization = ExactAuthorization {
        authorization_id: format!("auth-{run_id}"),
        operation_id: request.operation_id,
        namespace: request.namespace,
        deployment: request.deployment,
        container: request.container,
        immutable_image_digest: request.immutable_image_digest,
    };
    let grant = provision_exact_grant(&GrantProvisioning {
        authorization: &authorization,
        signing_seed: seed,
        signing_key_id: &key_id,
    })
    .map_err(|_| "authorization staging input is invalid")?;
    let trust =
        serde_json::to_vec(&identity).map_err(|_| "authorization staging input is invalid")?;
    let grant_body = secret(
        RUNNER_NAMESPACE,
        &format!("runner-grant-{run_id}"),
        run_labels(run_id, "authorization-grant"),
        [("signed-grant.json", grant.as_slice())],
    );
    let grant_observation = create_or_observe(client, &grant_body).await?;
    require_cleanup_owner(&grant_observation, run_id)?;
    let trust_body = config_map(
        RUNNER_NAMESPACE,
        &format!("runner-trust-{run_id}"),
        run_labels(run_id, "authorization-trust"),
        [(
            "trust.json",
            std::str::from_utf8(&trust).map_err(|_| "authorization staging input is invalid")?,
        )],
    );
    let trust_observation = create_or_observe(client, &trust_body).await?;
    require_cleanup_owner(&trust_observation, run_id)?;
    Ok(vec![grant_observation, trust_observation])
}

async fn stage_controller_tls(
    arguments: &Arguments,
    inputs: &LoadedInputs,
    client: &Client,
) -> Result<(), &'static str> {
    let ca = inputs.tls_ca.as_ref().ok_or("stager source is invalid")?;
    let certificate = inputs
        .tls_certificate
        .as_ref()
        .ok_or("stager source is invalid")?;
    let private_key = inputs
        .tls_private_key
        .as_ref()
        .ok_or("stager source is invalid")?;
    validate_controller_tls(
        ca,
        certificate,
        private_key,
        arguments.ca_sha256.ok_or("stager arguments are invalid")?,
        arguments
            .ca_root_count
            .ok_or("stager arguments are invalid")?,
    )?;
    let serving = secret(
        SYSTEM_NAMESPACE,
        "kapsel-controller-state-serving",
        system_labels("controller-tls"),
        [
            ("tls.crt", certificate.as_slice()),
            ("tls.key", private_key.as_slice()),
        ],
    );
    create_or_observe(client, &serving).await?;
    let roots = std::str::from_utf8(ca).map_err(|_| "controller TLS staging input is invalid")?;
    let trust = config_map(
        SYSTEM_NAMESPACE,
        "kapsel-controller-state-ca",
        system_labels("controller-tls"),
        [("ca.crt", roots)],
    );
    create_or_observe(client, &trust).await?;
    Ok(())
}

fn validate_request(run_id: &str, request: &RequestDocument) -> Result<(), &'static str> {
    if request.operation_id != format!("sandbox-{run_id}")
        || request.namespace != format!("sandbox-{run_id}")
        || request.deployment != "sandbox-target"
        || request.container != "target"
        || !matches!(
            request.immutable_image_digest.as_str(),
            HEALTHY_IMAGE | UNAVAILABLE_IMAGE
        )
    {
        return Err("authorization staging input is invalid");
    }
    Ok(())
}

fn system_labels(role: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("kapsel.dev/gate2".into(), "true".into()),
        ("kapsel.dev/staging-role".into(), role.into()),
    ])
}

fn run_labels(run_id: &str, role: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "kapsel.dev/cleanup-owner".into(),
            format!("cleanup-{run_id}"),
        ),
        ("kapsel.dev/sandbox-run-id".into(), run_id.into()),
        ("kapsel.dev/staging-role".into(), role.into()),
    ])
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "owned labels are consumed directly into the fixed rendered object"
)]
// Kubernetes requires base64/JSON-owned Secret request copies. They remain process-bounded and are
// dropped immediately after this one-shot role exits; feasible source and decoded-key buffers are
// separately zeroized.
fn secret<'a>(
    namespace: &str,
    name: &str,
    labels: BTreeMap<String, String>,
    entries: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> Value {
    let encoded_entries: serde_json::Map<String, Value> = entries
        .into_iter()
        .map(|(key, value)| (key.into(), Value::String(base64(value))))
        .collect();
    json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": name, "namespace": namespace, "labels": labels},
        "immutable": true,
        "type": "Opaque",
        "data": encoded_entries,
    })
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "owned labels are consumed directly into the fixed rendered object"
)]
fn config_map<'a>(
    namespace: &str,
    name: &str,
    labels: BTreeMap<String, String>,
    entries: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Value {
    let encoded_entries: serde_json::Map<String, Value> = entries
        .into_iter()
        .map(|(key, value)| (key.into(), Value::String(value.into())))
        .collect();
    json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": namespace, "labels": labels},
        "immutable": true,
        "data": encoded_entries,
    })
}

async fn create_or_observe(
    client: &Client,
    expected: &Value,
) -> Result<ObservedObject, &'static str> {
    let kind = expected["kind"]
        .as_str()
        .ok_or("staged object is invalid")?;
    let metadata = expected["metadata"]
        .as_object()
        .ok_or("staged object is invalid")?;
    let namespace = metadata["namespace"]
        .as_str()
        .ok_or("staged object is invalid")?;
    let name = metadata["name"]
        .as_str()
        .ok_or("staged object is invalid")?;
    let plural = match kind {
        "Secret" => "secrets",
        "ConfigMap" => "configmaps",
        _ => return Err("staged object is invalid"),
    };
    let resource =
        ApiResource::from_gvk_with_plural(&GroupVersionKind::gvk("", "v1", kind), plural);
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &resource);
    let object: DynamicObject =
        serde_json::from_value(expected.clone()).map_err(|_| "staged object is invalid")?;
    let observed = match timeout(
        API_DEADLINE,
        api.create(
            &PostParams {
                field_manager: Some(FIELD_MANAGER.into()),
                ..PostParams::default()
            },
            &object,
        ),
    )
    .await
    {
        Ok(Ok(created)) => created,
        Ok(Err(kube::Error::Api(response))) if response.code == 409 => {
            timeout(API_DEADLINE, api.get(name))
                .await
                .map_err(|_| "staging Kubernetes request failed")?
                .map_err(|_| "staging Kubernetes request failed")?
        },
        _ => return Err("staging Kubernetes request failed"),
    };
    exact_observation(
        expected,
        serde_json::to_value(observed).map_err(|_| "staged object is invalid")?,
    )
}

fn exact_observation(
    expected: &Value,
    mut observed: Value,
) -> Result<ObservedObject, &'static str> {
    let metadata = observed["metadata"]
        .as_object_mut()
        .ok_or("staged object did not match")?;
    let uid = metadata
        .remove("uid")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or("staged object did not match")?;
    crate::bounded_identity(&uid).map_err(|_| "staged object did not match")?;
    for field in ["resourceVersion", "creationTimestamp", "managedFields"] {
        metadata.remove(field);
    }
    if &observed != expected {
        return Err("staged object did not match");
    }
    let expected_metadata = expected["metadata"]
        .as_object()
        .ok_or("staged object did not match")?;
    let owner_label = expected_metadata["labels"]["kapsel.dev/cleanup-owner"]
        .as_str()
        .map(str::to_owned);
    Ok(ObservedObject {
        kind: expected["kind"]
            .as_str()
            .ok_or("staged object did not match")?
            .into(),
        namespace: expected_metadata["namespace"]
            .as_str()
            .ok_or("staged object did not match")?
            .into(),
        name: expected_metadata["name"]
            .as_str()
            .ok_or("staged object did not match")?
            .into(),
        uid,
        owner_label,
    })
}

fn require_cleanup_owner(observed: &ObservedObject, run_id: &str) -> Result<(), &'static str> {
    if observed.owner_label.as_deref() == Some(&format!("cleanup-{run_id}")) {
        Ok(())
    } else {
        Err("staged object did not match")
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one linear validation keeps private-key zeroization visible on every outcome"
)]
fn validate_controller_tls(
    ca: &[u8],
    cert: &[u8],
    key: &[u8],
    expected_ca_sha256: [u8; 32],
    expected_root_count: u8,
) -> Result<(), &'static str> {
    if <[u8; 32]>::from(Sha256::digest(ca)) != expected_ca_sha256 {
        return Err("controller TLS staging input is invalid");
    }
    let roots = pem_items(ca)?;
    if roots.len() != usize::from(expected_root_count)
        || !(1..=2).contains(&roots.len())
        || (roots.len() == 2 && roots[0].1 == roots[1].1)
    {
        return Err("controller TLS staging input is invalid");
    }
    let mut root_store = RootCertStore::empty();
    for (kind, bytes) in roots {
        if kind != SectionKind::Certificate {
            return Err("controller TLS staging input is invalid");
        }
        let (trailing, parsed) = parse_x509_certificate(&bytes)
            .map_err(|_| "controller TLS staging input is invalid")?;
        let constraints = parsed
            .basic_constraints()
            .map_err(|_| "controller TLS staging input is invalid")?
            .ok_or("controller TLS staging input is invalid")?;
        if !trailing.is_empty() || !constraints.value.ca || !parsed.validity().is_valid() {
            return Err("controller TLS staging input is invalid");
        }
        root_store
            .add(CertificateDer::from(bytes))
            .map_err(|_| "controller TLS staging input is invalid")?;
    }
    let mut certificates = pem_items(cert)?;
    if certificates.len() != 1 {
        return Err("controller TLS staging input is invalid");
    }
    let (certificate_kind, leaf) = certificates
        .pop()
        .ok_or("controller TLS staging input is invalid")?;
    if certificate_kind != SectionKind::Certificate {
        return Err("controller TLS staging input is invalid");
    }
    let (trailing, parsed) =
        parse_x509_certificate(&leaf).map_err(|_| "controller TLS staging input is invalid")?;
    if !trailing.is_empty()
        || !parsed.validity().is_valid()
        || parsed
            .basic_constraints()
            .map_err(|_| "controller TLS staging input is invalid")?
            .is_some_and(|value| value.value.ca)
    {
        return Err("controller TLS staging input is invalid");
    }
    let san = parsed
        .subject_alternative_name()
        .map_err(|_| "controller TLS staging input is invalid")?
        .ok_or("controller TLS staging input is invalid")?;
    if san.value.general_names.as_slice() != [GeneralName::DNSName(SERVER_DNS_NAME)] {
        return Err("controller TLS staging input is invalid");
    }
    let mut key_items = pem_items(key)?;
    if key_items.len() != 1 {
        for (_, bytes) in &mut key_items {
            bytes.zeroize();
        }
        return Err("controller TLS staging input is invalid");
    }
    let (key_kind, key_bytes) = key_items
        .pop()
        .ok_or("controller TLS staging input is invalid")?;
    let mut key_bytes = Zeroizing::new(key_bytes);
    let mut private_key = match key_kind {
        SectionKind::RsaPrivateKey => {
            PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(std::mem::take(&mut *key_bytes)))
        },
        SectionKind::PrivateKey => {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::mem::take(&mut *key_bytes)))
        },
        SectionKind::EcPrivateKey => {
            PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(std::mem::take(&mut *key_bytes)))
        },
        _ => return Err("controller TLS staging input is invalid"),
    };
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&private_key);
    // rustls-pki-types implements `Zeroize` for owned private-key DER; erase it on both outcomes.
    private_key.zeroize();
    let signing_key = signing_key.map_err(|_| "controller TLS staging input is invalid")?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| "controller TLS staging input is invalid")?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let certified_key =
        rustls::sign::CertifiedKey::new(vec![CertificateDer::from(leaf)], signing_key);
    certified_key
        .keys_match()
        .map_err(|_| "controller TLS staging input is invalid")?;
    let server_config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| "controller TLS staging input is invalid")?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
            certified_key,
        )));
    prove_handshake(client_config, server_config)
}

fn prove_handshake(client: ClientConfig, server: ServerConfig) -> Result<(), &'static str> {
    let name = ServerName::try_from(SERVER_DNS_NAME)
        .map_err(|_| "controller TLS staging input is invalid")?
        .to_owned();
    let mut client = ClientConnection::new(Arc::new(client), name)
        .map_err(|_| "controller TLS staging input is invalid")?;
    let mut server = ServerConnection::new(Arc::new(server))
        .map_err(|_| "controller TLS staging input is invalid")?;
    for _ in 0..8 {
        let mut wire = Vec::new();
        client
            .write_tls(&mut wire)
            .map_err(|_| "controller TLS staging input is invalid")?;
        if !wire.is_empty() {
            server
                .read_tls(&mut Cursor::new(wire))
                .map_err(|_| "controller TLS staging input is invalid")?;
            server
                .process_new_packets()
                .map_err(|_| "controller TLS staging input is invalid")?;
        }
        let mut wire = Vec::new();
        server
            .write_tls(&mut wire)
            .map_err(|_| "controller TLS staging input is invalid")?;
        if !wire.is_empty() {
            client
                .read_tls(&mut Cursor::new(wire))
                .map_err(|_| "controller TLS staging input is invalid")?;
            client
                .process_new_packets()
                .map_err(|_| "controller TLS staging input is invalid")?;
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    Err("controller TLS staging input is invalid")
}

fn pem_items(bytes: &[u8]) -> Result<Vec<(SectionKind, Vec<u8>)>, &'static str> {
    strict_pem_envelope(bytes)?;
    <(SectionKind, Vec<u8>)>::pem_slice_iter(bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "controller TLS staging input is invalid")
}

fn strict_pem_envelope(bytes: &[u8]) -> Result<(), &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "controller TLS staging input is invalid")?;
    let mut label = None;
    let mut content_lines = 0_usize;
    let mut blocks = 0_usize;
    for raw_line in text.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if let Some(begin) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|value| value.strip_suffix("-----"))
        {
            if label.is_some()
                || begin.is_empty()
                || !begin
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte == b' ' || byte.is_ascii_digit())
            {
                return Err("controller TLS staging input is invalid");
            }
            label = Some(begin);
            content_lines = 0;
        } else if let Some(end) = line
            .strip_prefix("-----END ")
            .and_then(|value| value.strip_suffix("-----"))
        {
            if label != Some(end) || content_lines == 0 {
                return Err("controller TLS staging input is invalid");
            }
            label = None;
            blocks += 1;
        } else if label.is_none()
            || line.is_empty()
            || line.len() > 64
            || !line
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return Err("controller TLS staging input is invalid");
        } else {
            content_lines += 1;
        }
    }
    if label.is_some() || blocks == 0 {
        Err("controller TLS staging input is invalid")
    } else {
        Ok(())
    }
}

fn load_inputs(arguments: &Arguments) -> Result<LoadedInputs, &'static str> {
    let opened = open_complete_inputs(arguments)?;
    let mut seed = None;
    let mut request = None;
    let mut key_identity = None;
    let mut tls_ca = None;
    let mut tls_certificate = None;
    let mut tls_private_key = None;
    let mut kubernetes_ca = None;
    let mut kubernetes_token = None;
    for input in opened {
        let kind = input.kind;
        let bytes = read_opened(input)?;
        match kind {
            InputKind::Seed => {
                let exact: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| "stager source is invalid")?;
                // `bytes` is zeroized on this scope exit; the fixed copy remains zeroizing-owned.
                seed = Some(Zeroizing::new(exact));
            },
            InputKind::Request => request = Some(bytes),
            InputKind::KeyIdentity => key_identity = Some(bytes),
            InputKind::TlsCa => tls_ca = Some(bytes),
            InputKind::TlsCertificate => tls_certificate = Some(bytes),
            InputKind::TlsPrivateKey => tls_private_key = Some(bytes),
            InputKind::KubernetesCa => kubernetes_ca = Some(bytes),
            InputKind::KubernetesToken => kubernetes_token = Some(bytes),
        }
    }
    Ok(LoadedInputs {
        seed,
        request,
        key_identity,
        tls_ca,
        tls_certificate,
        tls_private_key,
        kubernetes_ca: kubernetes_ca.ok_or("stager source is invalid")?,
        kubernetes_token: kubernetes_token.ok_or("stager source is invalid")?,
    })
}

fn open_complete_inputs(arguments: &Arguments) -> Result<Vec<OpenedInput>, &'static str> {
    validate_source_mount(&arguments.source_mount)?;
    let specifications = input_specifications(arguments)?;
    for (index, (_, path, _)) in specifications.iter().enumerate() {
        if specifications
            .iter()
            .skip(index + 1)
            .any(|(_, other, _)| path == other)
        {
            return Err("stager authority lanes must be distinct");
        }
    }
    let mut opened = Vec::with_capacity(specifications.len());
    for (kind, path, maximum) in specifications {
        let file = open_projected_or_regular(&path).map_err(|_| "stager source is unavailable")?;
        let metadata = file
            .metadata()
            .map_err(|_| "stager source is unavailable")?;
        validate_file_and_parent(&path, &metadata)?;
        opened.push(OpenedInput {
            kind,
            file,
            metadata,
            maximum,
        });
    }
    for (index, input) in opened.iter().enumerate() {
        if opened.iter().skip(index + 1).any(|other| {
            input.metadata.dev() == other.metadata.dev()
                && input.metadata.ino() == other.metadata.ino()
        }) {
            return Err("stager authority lanes must be distinct");
        }
    }
    Ok(opened)
}

fn input_specifications(
    arguments: &Arguments,
) -> Result<Vec<(InputKind, PathBuf, usize)>, &'static str> {
    if !arguments.source_mount.is_absolute()
        || arguments.kubernetes_ca.starts_with(&arguments.source_mount)
        || arguments
            .kubernetes_token
            .starts_with(&arguments.source_mount)
        || arguments.request.as_ref().is_some_and(|path| {
            path.starts_with(&arguments.source_mount) || path == &arguments.source_mount
        })
        || arguments.key_identity.as_ref().is_some_and(|path| {
            path.starts_with(&arguments.source_mount) || path == &arguments.source_mount
        })
    {
        return Err("stager authority lanes must be distinct");
    }
    let mut inputs = match arguments.role {
        Role::ControllerTls => vec![
            (
                InputKind::TlsCa,
                arguments.source_mount.join("ca.crt"),
                FILE_BYTES_MAX,
            ),
            (
                InputKind::TlsCertificate,
                arguments.source_mount.join("tls.crt"),
                FILE_BYTES_MAX,
            ),
            (
                InputKind::TlsPrivateKey,
                arguments.source_mount.join("tls.key"),
                FILE_BYTES_MAX,
            ),
        ],
        Role::Tombstone | Role::AuthorizationGrant | Role::ReceiptSigning => {
            vec![(InputKind::Seed, arguments.source_mount.join("seed"), 32)]
        },
    };
    if let Some(path) = arguments.request.as_ref() {
        inputs.push((InputKind::Request, path.clone(), REQUEST_BYTES_MAX));
    }
    if let Some(path) = arguments.key_identity.as_ref() {
        inputs.push((InputKind::KeyIdentity, path.clone(), 512));
    }
    inputs.push((
        InputKind::KubernetesCa,
        arguments.kubernetes_ca.clone(),
        FILE_BYTES_MAX,
    ));
    inputs.push((
        InputKind::KubernetesToken,
        arguments.kubernetes_token.clone(),
        16 * 1024,
    ));
    Ok(inputs)
}

fn validate_file_and_parent(path: &Path, metadata: &fs::Metadata) -> Result<(), &'static str> {
    let mode = metadata.permissions().mode() & 0o777;
    let owner =
        metadata.uid() == rustix::process::getuid().as_raw() && matches!(mode, 0o400 | 0o600);
    let group =
        metadata.gid() == rustix::process::getgid().as_raw() && matches!(mode, 0o440 | 0o640);
    let parent = path.parent().ok_or("stager source is invalid")?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| "stager source is invalid")?;
    let parent_mode = parent_metadata.permissions().mode() & 0o777;
    let private_parent = parent_metadata.uid() == rustix::process::getuid().as_raw()
        && matches!(parent_mode, 0o700 | 0o750);
    let group_parent =
        parent_metadata.gid() == rustix::process::getgid().as_raw() && parent_mode == 0o750;
    if !metadata.is_file()
        || (!owner && !group)
        || !parent_metadata.is_dir()
        || (!private_parent && !group_parent)
    {
        return Err("stager source is invalid");
    }
    Ok(())
}

fn read_opened(mut input: OpenedInput) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(input.maximum.min(4096) + 1));
    input
        .file
        .by_ref()
        .take(input.maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "stager source is unavailable")?;
    if bytes.is_empty() || bytes.len() > input.maximum {
        return Err("stager source is invalid");
    }
    Ok(bytes)
}

fn validate_source_mount(path: &Path) -> Result<(), &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "stager source is unavailable")?;
    let mode = metadata.permissions().mode() & 0o777;
    let owner =
        metadata.uid() == rustix::process::getuid().as_raw() && matches!(mode, 0o700 | 0o750);
    let group = metadata.gid() == rustix::process::getgid().as_raw() && mode == 0o750;
    if metadata.is_dir() && (owner || group) {
        Ok(())
    } else {
        Err("stager source is invalid")
    }
}

fn read_key_identity(inputs: &LoadedInputs) -> Result<KeyIdentityDocument, &'static str> {
    let bytes = inputs
        .key_identity
        .as_ref()
        .ok_or("stager arguments are invalid")?;
    let identity: KeyIdentityDocument =
        serde_json::from_slice(bytes).map_err(|_| "stager key identity is invalid")?;
    if identity.key_id.is_empty()
        || identity.key_id.len() > 128
        || !identity
            .key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || parse_sha256(&identity.public_key_hex).is_err()
        || serde_json::to_vec(&identity).map_err(|_| "stager key identity is invalid")? != **bytes
    {
        return Err("stager key identity is invalid");
    }
    Ok(identity)
}

fn require_seed_identity(
    seed: &[u8; 32],
    identity: &KeyIdentityDocument,
) -> Result<(), &'static str> {
    if hex(&SigningKey::from_bytes(seed).verifying_key().to_bytes()) == identity.public_key_hex {
        Ok(())
    } else {
        Err("stager key identity is invalid")
    }
}

fn projected_client(ca: &[u8], token: &[u8]) -> Result<Client, &'static str> {
    let host = env::var("KUBERNETES_SERVICE_HOST")
        .map_err(|_| "stager Kubernetes configuration is unavailable")?;
    let port = env::var("KUBERNETES_SERVICE_PORT")
        .map_err(|_| "stager Kubernetes configuration is unavailable")?;
    let cluster_url = format!("https://{host}:{port}")
        .parse()
        .map_err(|_| "stager Kubernetes configuration is unavailable")?;
    let roots = CertificateDer::pem_slice_iter(ca)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "stager Kubernetes configuration is unavailable")?;
    if roots.is_empty() {
        return Err("stager Kubernetes configuration is unavailable");
    }
    let token =
        std::str::from_utf8(token).map_err(|_| "stager Kubernetes configuration is unavailable")?;
    if token.is_empty() || token.contains(['\r', '\n']) {
        return Err("stager Kubernetes configuration is unavailable");
    }
    let mut config = kube::Config::new(cluster_url);
    config.root_cert = Some(
        roots
            .into_iter()
            .map(|root| root.as_ref().to_vec())
            .collect(),
    );
    config.root_cert_file = None;
    config.auth_info.token = Some(token.to_owned().into());
    config.auth_info.token_file = None;
    Client::try_from(config).map_err(|_| "stager Kubernetes client is unavailable")
}

#[cfg(test)]
fn validate_lanes(arguments: &Arguments) -> Result<(), &'static str> {
    open_complete_inputs(arguments).map(|_| ())
}

#[cfg(test)]
fn read_exact_32(arguments: &Arguments, _name: &str) -> Result<[u8; 32], &'static str> {
    load_inputs(arguments)?
        .seed
        .as_deref()
        .copied()
        .ok_or("stager source is invalid")
}

fn absolute(value: String) -> Result<PathBuf, &'static str> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err("stager arguments are invalid")
    }
}

fn parse_sha256(value: &str) -> Result<[u8; 32], &'static str> {
    if value.len() != 64 || !value.is_ascii() {
        return Err("stager arguments are invalid");
    }
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "stager arguments are invalid")?;
    }
    Ok(output)
}

fn valid_run_id(value: String) -> Result<String, &'static str> {
    if value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(value)
    } else {
        Err("stager arguments are invalid")
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            let _ = write!(output, "{byte:02x}");
            output
        },
    )
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(TABLE[((value >> 18) & 63) as usize] as char);
        output.push(TABLE[((value >> 12) & 63) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[((value >> 6) & 63) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(value & 63) as usize] as char
        } else {
            '='
        });
    }
    output
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::symlink,
        sync::atomic::{AtomicU64, Ordering},
    };

    use http::{Response, StatusCode};
    use kapsel::{Application, AuthorizationTrust, OperatorConfiguration};
    use tower_test::mock;

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn private_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "kapsel-stager-{}-{name}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::canonicalize(root).unwrap()
    }

    fn arguments(root: &Path, role: Role) -> Arguments {
        Arguments {
            role,
            source_mount: root.into(),
            request: (role == Role::AuthorizationGrant)
                .then(|| root.with_extension("request").join("request.json")),
            key_identity: matches!(role, Role::AuthorizationGrant | Role::ReceiptSigning)
                .then(|| root.with_extension("identity").join("key-identity.json")),
            run_id: matches!(role, Role::AuthorizationGrant | Role::ReceiptSigning)
                .then(|| RUN.into()),
            ca_sha256: (role == Role::ControllerTls).then_some([0; 32]),
            ca_root_count: (role == Role::ControllerTls).then_some(1),
            kubernetes_ca: root.with_extension("kubernetes-ca").join("ca.crt"),
            kubernetes_token: root.with_extension("kubernetes-token").join("token"),
        }
    }

    fn response(body: &Value, status: StatusCode) -> Response<kube::client::Body> {
        Response::builder()
            .status(status)
            .body(kube::client::Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap()
    }

    fn api_status(reason: &str, code: u16) -> Value {
        json!({
            "apiVersion": "v1",
            "kind": "Status",
            "status": "Failure",
            "reason": reason,
            "code": code,
        })
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir(parent).unwrap();
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn per_run_fixture(role: Role, seed: [u8; 32], key_id: &str) -> (PathBuf, Arguments) {
        let root = private_root(match role {
            Role::AuthorizationGrant => "grant-role",
            Role::ReceiptSigning => "receipt-role",
            _ => unreachable!(),
        });
        let arguments = arguments(&root, role);
        write_private(&root.join("seed"), &seed);
        let identity = KeyIdentityDocument {
            key_id: key_id.into(),
            public_key_hex: hex(&SigningKey::from_bytes(&seed).verifying_key().to_bytes()),
        };
        write_private(
            arguments.key_identity.as_ref().unwrap(),
            &serde_json::to_vec(&identity).unwrap(),
        );
        if let Some(request) = arguments.request.as_ref() {
            write_private(
                request,
                &serde_json::to_vec(&RequestDocument {
                    operation_id: format!("sandbox-{RUN}"),
                    namespace: format!("sandbox-{RUN}"),
                    deployment: "sandbox-target".into(),
                    container: "target".into(),
                    immutable_image_digest: HEALTHY_IMAGE.into(),
                })
                .unwrap(),
            );
        }
        write_private(&arguments.kubernetes_ca, b"kubernetes-ca");
        write_private(&arguments.kubernetes_token, b"kubernetes-token");
        (root, arguments)
    }

    fn observed(mut body: Value, uid: &str) -> Value {
        body["metadata"]["uid"] = json!(uid);
        body["metadata"]["resourceVersion"] = json!("1");
        body
    }

    const RUN: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn source_files_accept_private_and_atomic_writer_layout_but_reject_unsafe_inputs() {
        let root = private_root("source");
        let arguments = arguments(&root, Role::Tombstone);
        write_private(&arguments.kubernetes_ca, b"credential-ca");
        write_private(&arguments.kubernetes_token, b"credential-token");
        fs::write(root.join("seed"), [7_u8; 32]).unwrap();
        fs::set_permissions(root.join("seed"), fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_exact_32(&arguments, "seed").unwrap(), [7_u8; 32]);

        fs::write(root.join("seed"), [7_u8; 31]).unwrap();
        assert!(read_exact_32(&arguments, "seed").is_err());
        fs::write(root.join("seed"), [7_u8; 32]).unwrap();
        fs::set_permissions(root.join("seed"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_exact_32(&arguments, "seed").is_err());

        fs::remove_file(root.join("seed")).unwrap();
        let generation = root.join("..2026_07_26_00_00_00.000000001");
        fs::create_dir(&generation).unwrap();
        fs::set_permissions(&generation, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(generation.join("seed"), [8_u8; 32]).unwrap();
        fs::set_permissions(generation.join("seed"), fs::Permissions::from_mode(0o600)).unwrap();
        symlink(generation.file_name().unwrap(), root.join("..data")).unwrap();
        symlink("..data/seed", root.join("seed")).unwrap();
        assert_eq!(read_exact_32(&arguments, "seed").unwrap(), [8_u8; 32]);
        fs::remove_file(root.join("seed")).unwrap();
        symlink("../outside", root.join("seed")).unwrap();
        assert!(read_exact_32(&arguments, "seed").is_err());

        fs::remove_file(&arguments.kubernetes_token).unwrap();
        fs::hard_link(&arguments.kubernetes_ca, &arguments.kubernetes_token).unwrap();
        assert!(validate_lanes(&arguments).is_err());
        fs::remove_dir_all(root).unwrap();
        fs::remove_file(arguments.kubernetes_ca).unwrap();
        fs::remove_file(arguments.kubernetes_token).unwrap();
    }

    #[test]
    fn opened_snapshot_survives_path_replacement_and_missing_lanes_fail_closed() {
        let root = private_root("stable-descriptors");
        let arguments = arguments(&root, Role::Tombstone);
        write_private(&root.join("seed"), &[7; 32]);
        write_private(&arguments.kubernetes_ca, b"credential-ca");
        write_private(&arguments.kubernetes_token, b"credential-token");
        let opened = open_complete_inputs(&arguments).unwrap();
        fs::remove_file(root.join("seed")).unwrap();
        write_private(&root.join("seed"), &[8; 32]);
        fs::remove_file(&arguments.kubernetes_token).unwrap();
        write_private(&arguments.kubernetes_token, b"replacement-token");
        let mut original_seed = None;
        let mut original_token = None;
        for input in opened {
            match input.kind {
                InputKind::Seed => original_seed = Some(read_opened(input).unwrap()),
                InputKind::KubernetesToken => {
                    original_token = Some(read_opened(input).unwrap());
                },
                _ => {},
            }
        }
        assert_eq!(&**original_seed.as_ref().unwrap(), &[7; 32]);
        assert_eq!(&**original_token.as_ref().unwrap(), b"credential-token");

        fs::remove_file(&arguments.kubernetes_token).unwrap();
        assert!(open_complete_inputs(&arguments).is_err());
    }

    #[test]
    fn request_and_identity_parents_and_private_lane_hard_links_fail_closed() {
        let (root, arguments) = per_run_fixture(Role::AuthorizationGrant, [9; 32], "grant-key");
        validate_lanes(&arguments).unwrap();
        let request = arguments.request.as_ref().unwrap();
        let identity = arguments.key_identity.as_ref().unwrap();

        fs::set_permissions(request.parent().unwrap(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(load_inputs(&arguments).is_err());
        fs::set_permissions(request.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            identity.parent().unwrap(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(load_inputs(&arguments).is_err());
        fs::set_permissions(
            identity.parent().unwrap(),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();

        fs::remove_file(identity).unwrap();
        fs::hard_link(request, identity).unwrap();
        assert!(validate_lanes(&arguments).is_err());
        fs::remove_file(identity).unwrap();
        fs::hard_link(root.join("seed"), identity).unwrap();
        assert!(validate_lanes(&arguments).is_err());
    }

    #[test]
    fn fixed_secret_schemas_contain_only_exact_immutable_data() {
        let tombstone = secret(
            SYSTEM_NAMESPACE,
            "kapsel-gate2-tombstone-digest",
            system_labels("tombstone"),
            [("tombstone-digest.seed", &[7_u8; 32][..])],
        );
        assert_eq!(tombstone["immutable"], true);
        assert_eq!(tombstone["data"].as_object().unwrap().len(), 1);
        let receipt = secret(
            RUNNER_NAMESPACE,
            &format!("runner-receipt-signing-{RUN}"),
            run_labels(RUN, "receipt-signing"),
            [("seed", &[8_u8; 32][..]), ("key-id", b"receipt-key")],
        );
        assert_eq!(receipt["data"].as_object().unwrap().len(), 2);
        assert_eq!(
            receipt["metadata"]["labels"]["kapsel.dev/cleanup-owner"],
            format!("cleanup-{RUN}")
        );
    }

    #[tokio::test]
    #[allow(
        clippy::similar_names,
        reason = "seed and mock response sender are distinct test-domain values"
    )]
    async fn authorization_role_posts_exact_objects_and_returns_sanitized_ordered_metadata() {
        let seed = [9_u8; 32];
        let (root, arguments) = per_run_fixture(Role::AuthorizationGrant, seed, "grant-key");
        validate_lanes(&arguments).unwrap();
        let authorization = ExactAuthorization {
            authorization_id: format!("auth-{RUN}"),
            operation_id: format!("sandbox-{RUN}"),
            namespace: format!("sandbox-{RUN}"),
            deployment: "sandbox-target".into(),
            container: "target".into(),
            immutable_image_digest: HEALTHY_IMAGE.into(),
        };
        let grant = provision_exact_grant(&GrantProvisioning {
            authorization: &authorization,
            signing_seed: &seed,
            signing_key_id: "grant-key",
        })
        .unwrap();
        let expected_grant = secret(
            RUNNER_NAMESPACE,
            &format!("runner-grant-{RUN}"),
            run_labels(RUN, "authorization-grant"),
            [("signed-grant.json", grant.as_slice())],
        );
        let identity = fs::read_to_string(arguments.key_identity.as_ref().unwrap()).unwrap();
        let expected_trust = config_map(
            RUNNER_NAMESPACE,
            &format!("runner-trust-{RUN}"),
            run_labels(RUN, "authorization-trust"),
            [("trust.json", identity.as_str())],
        );
        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let grant_response = observed(expected_grant.clone(), "grant-uid");
        let trust_response = observed(expected_trust.clone(), "trust-uid");
        let server = tokio::spawn(async move {
            for (path, expected, reply) in [
                (
                    "/api/v1/namespaces/kapsel-sandbox-runners/secrets",
                    expected_grant,
                    grant_response,
                ),
                (
                    "/api/v1/namespaces/kapsel-sandbox-runners/configmaps",
                    expected_trust,
                    trust_response,
                ),
            ] {
                let (request, send) = handle.next_request().await.unwrap();
                assert_eq!(request.method(), http::Method::POST);
                assert_eq!(request.uri().path(), path);
                let body: Value =
                    serde_json::from_slice(&request.into_body().collect_bytes().await.unwrap())
                        .unwrap();
                assert_eq!(body, expected);
                send.send_response(response(&reply, StatusCode::CREATED));
            }
        });
        let loaded = load_inputs(&arguments).unwrap();
        let result =
            stage_authorization_grant(&arguments, &loaded, &Client::new(transport, "default"))
                .await
                .unwrap();
        assert_eq!(
            result,
            vec![
                ObservedObject {
                    kind: "Secret".into(),
                    namespace: RUNNER_NAMESPACE.into(),
                    name: format!("runner-grant-{RUN}"),
                    uid: "grant-uid".into(),
                    owner_label: Some(format!("cleanup-{RUN}")),
                },
                ObservedObject {
                    kind: "ConfigMap".into(),
                    namespace: RUNNER_NAMESPACE.into(),
                    name: format!("runner-trust-{RUN}"),
                    uid: "trust-uid".into(),
                    owner_label: Some(format!("cleanup-{RUN}")),
                },
            ]
        );
        let encoded: Value = serde_json::from_str(&encode_result(result).unwrap()).unwrap();
        assert_eq!(encoded["protocol"], "key-staging-result-v1");
        assert_eq!(encoded["objects"].as_array().map(Vec::len), Some(2));
        assert_eq!(encoded["objects"][0]["uid"], "grant-uid");
        assert_eq!(encoded["objects"][1]["uid"], "trust-uid");
        server.await.unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    #[allow(
        clippy::similar_names,
        clippy::too_many_lines,
        reason = "one recovery test keeps the exact three-request retry sequence visible"
    )]
    async fn authorization_partial_failure_retries_grant_exactly_then_creates_trust() {
        let seed = [9_u8; 32];
        let (_root, arguments) = per_run_fixture(Role::AuthorizationGrant, seed, "grant-key");
        validate_lanes(&arguments).unwrap();
        let authorization = ExactAuthorization {
            authorization_id: format!("auth-{RUN}"),
            operation_id: format!("sandbox-{RUN}"),
            namespace: format!("sandbox-{RUN}"),
            deployment: "sandbox-target".into(),
            container: "target".into(),
            immutable_image_digest: HEALTHY_IMAGE.into(),
        };
        let grant = provision_exact_grant(&GrantProvisioning {
            authorization: &authorization,
            signing_seed: &seed,
            signing_key_id: "grant-key",
        })
        .unwrap();
        let grant_body = secret(
            RUNNER_NAMESPACE,
            &format!("runner-grant-{RUN}"),
            run_labels(RUN, "authorization-grant"),
            [("signed-grant.json", grant.as_slice())],
        );
        let identity = fs::read_to_string(arguments.key_identity.as_ref().unwrap()).unwrap();
        let trust_body = config_map(
            RUNNER_NAMESPACE,
            &format!("runner-trust-{RUN}"),
            run_labels(RUN, "authorization-trust"),
            [("trust.json", identity.as_str())],
        );

        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let first_grant = observed(grant_body.clone(), "grant-stable-uid");
        let first_server = tokio::spawn(async move {
            let (request, send) = handle.next_request().await.unwrap();
            assert_eq!(
                request.uri().path(),
                "/api/v1/namespaces/kapsel-sandbox-runners/secrets"
            );
            send.send_response(response(&first_grant, StatusCode::CREATED));
            let (request, send) = handle.next_request().await.unwrap();
            assert_eq!(
                request.uri().path(),
                "/api/v1/namespaces/kapsel-sandbox-runners/configmaps"
            );
            send.send_response(response(
                &api_status("InternalError", 500),
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        });
        assert!(stage_authorization_grant(
            &arguments,
            &load_inputs(&arguments).unwrap(),
            &Client::new(transport, "default"),
        )
        .await
        .is_err());
        first_server.await.unwrap();

        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let existing_grant = observed(grant_body.clone(), "grant-stable-uid");
        let created_trust = observed(trust_body.clone(), "trust-new-uid");
        let retry_server = tokio::spawn(async move {
            let (post, send) = handle.next_request().await.unwrap();
            assert_eq!(post.method(), http::Method::POST);
            assert_eq!(
                serde_json::from_slice::<Value>(&post.into_body().collect_bytes().await.unwrap())
                    .unwrap(),
                grant_body
            );
            send.send_response(response(
                &api_status("AlreadyExists", 409),
                StatusCode::CONFLICT,
            ));
            let (get, send) = handle.next_request().await.unwrap();
            assert_eq!(get.method(), http::Method::GET);
            assert_eq!(
                get.uri().path(),
                format!("/api/v1/namespaces/{RUNNER_NAMESPACE}/secrets/runner-grant-{RUN}")
            );
            send.send_response(response(&existing_grant, StatusCode::OK));
            let (post, send) = handle.next_request().await.unwrap();
            assert_eq!(post.method(), http::Method::POST);
            assert_eq!(
                serde_json::from_slice::<Value>(&post.into_body().collect_bytes().await.unwrap())
                    .unwrap(),
                trust_body
            );
            send.send_response(response(&created_trust, StatusCode::CREATED));
            assert!(matches!(
                tokio::time::timeout(Duration::from_millis(50), handle.next_request()).await,
                Err(_) | Ok(None)
            ));
        });
        let retry_inputs = load_inputs(&arguments).unwrap();
        let converged = stage_authorization_grant(
            &arguments,
            &retry_inputs,
            &Client::new(transport, "default"),
        )
        .await
        .unwrap();
        assert_eq!(converged[0].uid, "grant-stable-uid");
        assert_eq!(converged[1].uid, "trust-new-uid");
        retry_server.await.unwrap();
    }

    #[tokio::test]
    #[allow(
        clippy::similar_names,
        reason = "seed and mock response sender are distinct test-domain values"
    )]
    async fn receipt_role_posts_exact_projected_bytes_and_application_accepts_the_identity() {
        let seed = [8_u8; 32];
        let (root, arguments) = per_run_fixture(Role::ReceiptSigning, seed, "receipt-key");
        fs::remove_file(root.join("seed")).unwrap();
        let generation = root.join("..2026_07_26_00_00_00.000000002");
        fs::create_dir(&generation).unwrap();
        fs::set_permissions(&generation, fs::Permissions::from_mode(0o700)).unwrap();
        write_private(&generation.join("seed"), &seed);
        symlink(generation.file_name().unwrap(), root.join("..data")).unwrap();
        symlink("..data/seed", root.join("seed")).unwrap();
        validate_lanes(&arguments).unwrap();
        let expected = secret(
            RUNNER_NAMESPACE,
            &format!("runner-receipt-signing-{RUN}"),
            run_labels(RUN, "receipt-signing"),
            [("seed", seed.as_slice()), ("key-id", b"receipt-key")],
        );
        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let created = observed(expected.clone(), "receipt-uid");
        let server = tokio::spawn(async move {
            let (request, send) = handle.next_request().await.unwrap();
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(
                request.uri().path(),
                "/api/v1/namespaces/kapsel-sandbox-runners/secrets"
            );
            let body: Value =
                serde_json::from_slice(&request.into_body().collect_bytes().await.unwrap())
                    .unwrap();
            assert_eq!(body, expected);
            send.send_response(response(&created, StatusCode::CREATED));
        });
        let loaded = load_inputs(&arguments).unwrap();
        let metadata =
            stage_receipt_signing(&arguments, &loaded, &Client::new(transport, "default"))
                .await
                .unwrap();
        assert_eq!(metadata.name, format!("runner-receipt-signing-{RUN}"));
        assert_eq!(metadata.uid, "receipt-uid");
        server.await.unwrap();

        let grant_seed = [9_u8; 32];
        let grant_key = SigningKey::from_bytes(&grant_seed);
        let authorization = ExactAuthorization {
            authorization_id: format!("auth-{RUN}"),
            operation_id: format!("sandbox-{RUN}"),
            namespace: format!("sandbox-{RUN}"),
            deployment: "sandbox-target".into(),
            container: "target".into(),
            immutable_image_digest: HEALTHY_IMAGE.into(),
        };
        let grant = provision_exact_grant(&GrantProvisioning {
            authorization: &authorization,
            signing_seed: &grant_seed,
            signing_key_id: "grant-key",
        })
        .unwrap();
        let receipts = root.join("receipts");
        fs::create_dir(&receipts).unwrap();
        fs::set_permissions(&receipts, fs::Permissions::from_mode(0o700)).unwrap();
        let (transport, _handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        Application::open(OperatorConfiguration {
            journal_path: root.join("gateway.sqlite3"),
            receipt_output_directory: receipts,
            authorization_trust: AuthorizationTrust {
                key_id: "grant-key".into(),
                public_key: grant_key.verifying_key().to_bytes(),
            },
            signed_authorization_grant: grant,
            kubernetes_client: Client::new(transport, "default"),
            receipt_signing_seed: seed,
            receipt_signing_key_id: "receipt-key".into(),
        })
        .unwrap();
    }

    #[tokio::test]
    async fn grant_request_is_server_owned_and_trust_json_is_canonical() {
        let valid = RequestDocument {
            operation_id: format!("sandbox-{RUN}"),
            namespace: format!("sandbox-{RUN}"),
            deployment: "sandbox-target".into(),
            container: "target".into(),
            immutable_image_digest: HEALTHY_IMAGE.into(),
        };
        validate_request(RUN, &valid).unwrap();
        let changed = RequestDocument {
            deployment: "other".into(),
            ..valid
        };
        assert!(validate_request(RUN, &changed).is_err());
        let key = SigningKey::from_bytes(&[9; 32]);
        let trust = serde_json::to_string(&KeyIdentityDocument {
            key_id: "grant-key".into(),
            public_key_hex: hex(&key.verifying_key().to_bytes()),
        })
        .unwrap();
        assert!(trust.starts_with("{\"key_id\":\"grant-key\",\"public_key_hex\":\""));

        let authorization = ExactAuthorization {
            authorization_id: format!("auth-{RUN}"),
            operation_id: format!("sandbox-{RUN}"),
            namespace: format!("sandbox-{RUN}"),
            deployment: "sandbox-target".into(),
            container: "target".into(),
            immutable_image_digest: HEALTHY_IMAGE.into(),
        };
        let grant = provision_exact_grant(&GrantProvisioning {
            authorization: &authorization,
            signing_seed: &[9; 32],
            signing_key_id: "grant-key",
        })
        .unwrap();
        let root = private_root("application");
        let receipts = root.join("receipts");
        fs::create_dir(&receipts).unwrap();
        fs::set_permissions(&receipts, fs::Permissions::from_mode(0o700)).unwrap();
        let (transport, _handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        Application::open(OperatorConfiguration {
            journal_path: root.join("gateway.sqlite3"),
            receipt_output_directory: receipts,
            authorization_trust: AuthorizationTrust {
                key_id: "grant-key".into(),
                public_key: key.verifying_key().to_bytes(),
            },
            signed_authorization_grant: grant,
            kubernetes_client: Client::new(transport, "default"),
            receipt_signing_seed: [8; 32],
            receipt_signing_key_id: "receipt-key".into(),
        })
        .unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exact_observation_allows_only_named_server_identity_fields() {
        let expected = secret(
            SYSTEM_NAMESPACE,
            "kapsel-gate2-tombstone-digest",
            system_labels("tombstone"),
            [("tombstone-digest.seed", &[7_u8; 32][..])],
        );
        let mut observed = expected.clone();
        observed["metadata"]["uid"] = json!("uid-1");
        observed["metadata"]["resourceVersion"] = json!("2");
        let metadata = exact_observation(&expected, observed.clone()).unwrap();
        assert_eq!(metadata.uid, "uid-1");
        assert_eq!(
            encode_result(vec![metadata]).unwrap(),
            concat!(
                "{\"protocol\":\"key-staging-result-v1\",\"objects\":[{",
                "\"kind\":\"Secret\",\"namespace\":\"kapsel-sandbox-system\",",
                "\"name\":\"kapsel-gate2-tombstone-digest\",\"uid\":\"uid-1\",",
                "\"owner_label\":null}]}"
            )
        );
        observed["data"]["extra"] = json!("bad");
        assert!(exact_observation(&expected, observed).is_err());
    }

    #[test]
    fn owned_rustls_private_key_der_supports_explicit_zeroization() {
        let mut key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![7_u8; 32]));
        assert!(key.secret_der().iter().all(|byte| *byte == 7));
        key.zeroize();
        assert!(key.secret_der().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn tls_fixture_proves_chain_san_validity_key_match_and_rotation_bundle() {
        let fixtures =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/controller-transport");
        let root = fixtures.join("current");
        let ca = fs::read(root.join("ca.pem")).unwrap();
        let cert = fs::read(root.join("cert.pem")).unwrap();
        let key = fs::read(root.join("key.pem")).unwrap();
        let digest = Sha256::digest(&ca).into();
        validate_controller_tls(&ca, &cert, &key, digest, 1).unwrap();
        assert!(validate_controller_tls(
            &ca,
            &fs::read(fixtures.join("wrong-name/cert.pem")).unwrap(),
            &key,
            digest,
            1,
        )
        .is_err());
        assert!(validate_controller_tls(
            &ca,
            &cert,
            &fs::read(fixtures.join("wrong-name/key.pem")).unwrap(),
            digest,
            1,
        )
        .is_err());
        for invalid in ["expired", "future"] {
            let invalid_root = fixtures.join(invalid);
            let invalid_ca = fs::read(invalid_root.join("ca.pem")).unwrap();
            assert!(validate_controller_tls(
                &invalid_ca,
                &fs::read(invalid_root.join("cert.pem")).unwrap(),
                &fs::read(invalid_root.join("key.pem")).unwrap(),
                Sha256::digest(&invalid_ca).into(),
                1,
            )
            .is_err());
        }
        assert!(
            validate_controller_tls(&cert, &cert, &key, Sha256::digest(&cert).into(), 1).is_err()
        );
        let mut two_roots = ca.clone();
        two_roots.extend_from_slice(&fs::read(fixtures.join("wrong-name/ca.pem")).unwrap());
        validate_controller_tls(
            &two_roots,
            &cert,
            &key,
            Sha256::digest(&two_roots).into(),
            2,
        )
        .unwrap();
        assert!(validate_controller_tls(&two_roots, &cert, &key, digest, 2).is_err());
        let mut trailing = cert;
        trailing.extend_from_slice(b"unexpected");
        assert!(validate_controller_tls(&ca, &trailing, &key, digest, 1).is_err());
        assert!(validate_controller_tls(&ca, b"not pem", &key, digest, 1).is_err());
    }

    #[tokio::test]
    async fn kubernetes_create_and_conflict_observe_are_exact_and_never_update() {
        let expected = secret(
            SYSTEM_NAMESPACE,
            "kapsel-gate2-tombstone-digest",
            system_labels("tombstone"),
            [("tombstone-digest.seed", &[7_u8; 32][..])],
        );
        let mut observed = expected.clone();
        observed["metadata"]["uid"] = json!("uid-created");
        observed["metadata"]["resourceVersion"] = json!("1");
        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let expected_post = expected.clone();
        let server = tokio::spawn(async move {
            let (request, send) = handle.next_request().await.unwrap();
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(
                request.uri().path(),
                "/api/v1/namespaces/kapsel-sandbox-system/secrets"
            );
            let posted: Value =
                serde_json::from_slice(&request.into_body().collect_bytes().await.unwrap())
                    .unwrap();
            assert_eq!(posted, expected_post);
            send.send_response(response(&observed, StatusCode::CREATED));
        });
        assert_eq!(
            create_or_observe(&Client::new(transport, "default"), &expected)
                .await
                .unwrap()
                .uid,
            "uid-created"
        );
        server.await.unwrap();

        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let expected_for_server = expected.clone();
        let server = tokio::spawn(async move {
            let (request, send) = handle.next_request().await.unwrap();
            assert_eq!(request.method(), http::Method::POST);
            send.send_response(response(
                &api_status("AlreadyExists", 409),
                StatusCode::CONFLICT,
            ));
            let (request, send) = handle.next_request().await.unwrap();
            assert_eq!(request.method(), http::Method::GET);
            assert_eq!(
                request.uri().path(),
                "/api/v1/namespaces/kapsel-sandbox-system/secrets/kapsel-gate2-tombstone-digest"
            );
            let mut exact = expected_for_server;
            exact["metadata"]["uid"] = json!("uid-existing");
            send.send_response(response(&exact, StatusCode::OK));
            assert!(matches!(
                tokio::time::timeout(Duration::from_millis(50), handle.next_request()).await,
                Err(_) | Ok(None)
            ));
        });
        assert_eq!(
            create_or_observe(&Client::new(transport, "default"), &expected)
                .await
                .unwrap()
                .uid,
            "uid-existing"
        );
        server.await.unwrap();
    }

    #[test]
    fn hostile_uid_owner_immutable_data_and_metadata_are_rejected() {
        let expected = secret(
            RUNNER_NAMESPACE,
            &format!("runner-receipt-signing-{RUN}"),
            run_labels(RUN, "receipt-signing"),
            [("seed", &[8_u8; 32][..]), ("key-id", b"receipt-key")],
        );
        for mutation in ["uid", "owner", "immutable", "data", "metadata"] {
            let mut observed = expected.clone();
            observed["metadata"]["uid"] = json!("uid-existing");
            match mutation {
                "uid" => observed["metadata"]["uid"] = json!("INVALID UID"),
                "owner" => {
                    observed["metadata"]["labels"]["kapsel.dev/cleanup-owner"] = json!("other");
                },
                "immutable" => observed["immutable"] = json!(false),
                "data" => observed["data"]["seed"] = json!("Y2hhbmdlZA=="),
                "metadata" => observed["metadata"]["annotations"] = json!({"extra":"value"}),
                _ => unreachable!(),
            }
            assert!(
                exact_observation(&expected, observed).is_err(),
                "{mutation}"
            );
        }
    }

    #[tokio::test]
    async fn kubernetes_api_error_and_timeout_fail_without_followup_request() {
        let expected = secret(
            SYSTEM_NAMESPACE,
            "kapsel-gate2-tombstone-digest",
            system_labels("tombstone"),
            [("tombstone-digest.seed", &[7_u8; 32][..])],
        );
        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let server = tokio::spawn(async move {
            let (_, send) = handle.next_request().await.unwrap();
            send.send_response(response(
                &api_status("InternalError", 500),
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
            assert!(matches!(
                tokio::time::timeout(Duration::from_millis(50), handle.next_request()).await,
                Err(_) | Ok(None)
            ));
        });
        assert!(
            create_or_observe(&Client::new(transport, "default"), &expected)
                .await
                .is_err()
        );
        server.await.unwrap();

        let (transport, mut handle) =
            mock::pair::<http::Request<kube::client::Body>, http::Response<kube::client::Body>>();
        let server = tokio::spawn(async move {
            let (_request, _send) = handle.next_request().await.unwrap();
            tokio::time::sleep(API_DEADLINE + Duration::from_millis(100)).await;
            assert!(matches!(
                tokio::time::timeout(Duration::from_millis(50), handle.next_request()).await,
                Err(_) | Ok(None)
            ));
        });
        assert!(
            create_or_observe(&Client::new(transport, "default"), &expected)
                .await
                .is_err()
        );
        server.await.unwrap();
    }

    #[test]
    fn base64_known_answers_are_exact() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
    }
}
