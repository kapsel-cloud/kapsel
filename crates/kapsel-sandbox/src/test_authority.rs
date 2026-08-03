use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::AuthorityConfiguration;

const NAMES: [&str; 13] = [
    "authorization-signing-seed",
    "authorization-signing-key-id",
    "receipt-signing-seed",
    "receipt-signing-key-id",
    "tombstone-digest-key",
    "runner-kubernetes-api-server",
    "runner-kubernetes-ca.pem",
    "runner-kubernetes-token",
    "cleanup-kubernetes-api-server",
    "cleanup-kubernetes-ca.pem",
    "cleanup-kubernetes-token",
    "handoff-endpoint",
    "public-receipt-trust.json",
];

#[derive(Serialize)]
struct Manifest<'a> {
    version: u8,
    generation: u64,
    previous_generation: Option<u64>,
    files: Vec<ManifestFile<'a>>,
}
#[derive(Serialize)]
struct ManifestFile<'a> {
    name: &'a str,
    length: u64,
    sha256: String,
}
#[derive(Serialize)]
struct Current {
    version: u8,
    generation: u64,
    manifest_digest: String,
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02x}").unwrap();
            output
        },
    )
}

fn private_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn manifest_bytes(
    generation: u64,
    previous_generation: Option<u64>,
    digest_key: [u8; 32],
) -> Vec<u8> {
    let files = NAMES
        .iter()
        .map(|name| {
            let payload = if *name == "tombstone-digest-key" {
                digest_key.to_vec()
            } else {
                vec![u8::try_from(generation).unwrap()]
            };
            ManifestFile {
                name,
                length: u64::try_from(payload.len()).unwrap(),
                sha256: lower_hex(&Sha256::digest(&payload)),
            }
        })
        .collect();
    serde_json::to_vec(&Manifest {
        version: 1,
        generation,
        previous_generation,
        files,
    })
    .unwrap()
}

pub(crate) fn manifest_digest(digest_key: [u8; 32]) -> String {
    lower_hex(&Sha256::digest(manifest_bytes(1, None, digest_key)))
}

pub(crate) fn root(parent: &Path, digest_key: [u8; 32]) -> PathBuf {
    let authority = parent.join("fixed-authority");
    if authority.exists() {
        return authority;
    }
    private_directory(&authority);
    private_directory(&authority.join("incoming"));
    private_directory(&authority.join("generations"));
    private_directory(&authority.join("dispatch"));
    let generation = authority.join("generations/generation-00000000000000000001");
    private_directory(&generation);
    for name in NAMES {
        let payload = if name == "tombstone-digest-key" {
            digest_key.to_vec()
        } else {
            vec![1_u8]
        };
        fs::write(generation.join(name), &payload).unwrap();
        fs::set_permissions(generation.join(name), fs::Permissions::from_mode(0o400)).unwrap();
    }
    let manifest = manifest_bytes(1, None, digest_key);
    let manifest_digest = lower_hex(&Sha256::digest(&manifest));
    fs::write(generation.join("manifest.json"), manifest).unwrap();
    fs::set_permissions(
        generation.join("manifest.json"),
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    fs::set_permissions(&generation, fs::Permissions::from_mode(0o500)).unwrap();
    fs::write(
        authority.join("current"),
        serde_json::to_vec(&Current {
            version: 1,
            generation: 1,
            manifest_digest,
        })
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(authority.join("current"), fs::Permissions::from_mode(0o400)).unwrap();
    authority
}

pub(crate) fn configure_cleanup(root: &Path, endpoint: &str) {
    update_generation_one(
        root,
        &[
            ("cleanup-kubernetes-api-server", endpoint.as_bytes()),
            (
                "cleanup-kubernetes-ca.pem",
                include_bytes!("../tests/fixtures/localhost-ca.pem").as_slice(),
            ),
            ("cleanup-kubernetes-token", b"cleanup-token".as_slice()),
        ],
    );
}

pub(crate) fn configure_receipt_trust(root: &Path) -> Vec<u8> {
    let seed = [42_u8; 32];
    let trust = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "key_id": "sandbox-receipt-key",
        "public_key_hex": lower_hex(
            &ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes()
        ),
        "accepted_purpose": "kapsel.kap0038.kubernetes-effect-receipt.v2",
        "not_before_unix_s": 1,
        "not_after_unix_s": i64::MAX,
    }))
    .unwrap();
    update_generation_one(
        root,
        &[
            ("receipt-signing-seed", &seed),
            ("receipt-signing-key-id", b"sandbox-receipt-key"),
            ("public-receipt-trust.json", &trust),
        ],
    );
    trust
}

fn update_generation_one(root: &Path, files: &[(&str, &[u8])]) {
    let generation = root.join("fixed-authority/generations/generation-00000000000000000001");
    for (name, bytes) in files {
        let path = generation.join(name);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
    }
    let manifest = manifest_from_directory(&generation, 1, None);
    let manifest_digest = lower_hex(&Sha256::digest(&manifest));
    let manifest_path = generation.join("manifest.json");
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&manifest_path, manifest).unwrap();
    fs::set_permissions(manifest_path, fs::Permissions::from_mode(0o400)).unwrap();
    let current = root.join("fixed-authority/current");
    fs::set_permissions(&current, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(
        &current,
        serde_json::to_vec(&Current {
            version: 1,
            generation: 1,
            manifest_digest,
        })
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(current, fs::Permissions::from_mode(0o400)).unwrap();
}

fn manifest_from_directory(
    directory: &Path,
    generation: u64,
    previous_generation: Option<u64>,
) -> Vec<u8> {
    let files = NAMES
        .iter()
        .map(|name| {
            let payload = fs::read(directory.join(name)).unwrap();
            ManifestFile {
                name,
                length: u64::try_from(payload.len()).unwrap(),
                sha256: lower_hex(&Sha256::digest(&payload)),
            }
        })
        .collect();
    serde_json::to_vec(&Manifest {
        version: 1,
        generation,
        previous_generation,
        files,
    })
    .unwrap()
}

pub(crate) fn rotate(root: &Path, digest_key: [u8; 32]) -> crate::GenerationIdentity {
    let generation_number = 2;
    let generation = root
        .join("fixed-authority/generations")
        .join("generation-00000000000000000002");
    private_directory(&generation);
    for name in NAMES {
        let payload = if name == "tombstone-digest-key" {
            digest_key.to_vec()
        } else {
            vec![2_u8]
        };
        fs::write(generation.join(name), &payload).unwrap();
        fs::set_permissions(generation.join(name), fs::Permissions::from_mode(0o400)).unwrap();
    }
    let manifest = manifest_bytes(generation_number, Some(1), digest_key);
    let digest = lower_hex(&Sha256::digest(&manifest));
    fs::write(generation.join("manifest.json"), manifest).unwrap();
    fs::set_permissions(
        generation.join("manifest.json"),
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    fs::set_permissions(&generation, fs::Permissions::from_mode(0o500)).unwrap();
    let current = root.join("fixed-authority/current");
    fs::set_permissions(&current, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(
        &current,
        serde_json::to_vec(&Current {
            version: 1,
            generation: generation_number,
            manifest_digest: digest.clone(),
        })
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(current, fs::Permissions::from_mode(0o400)).unwrap();
    crate::GenerationIdentity::new(generation_number, digest).unwrap()
}

pub(crate) fn cleanup_service(
    name: &str,
    cleanup_endpoint: Option<&str>,
) -> (PathBuf, crate::Service, String) {
    let fixture_root =
        std::env::temp_dir().join(format!("kapsel-cleanup-role-{name}-{}", std::process::id()));
    if fixture_root.exists() {
        remove_root(&fixture_root);
    }
    private_directory(&fixture_root);
    private_directory(&fixture_root.join("receipts"));
    root(&fixture_root, [7; 32]);
    if let Some(endpoint) = cleanup_endpoint {
        configure_cleanup(&fixture_root, endpoint);
    }
    let service = crate::Service::open_for_test(
        fixture_root.join("sandbox.sqlite3"),
        fixture_root.join("receipts"),
        [7; 32],
        1_800_000_000,
    )
    .unwrap();
    let admission = service
        .admit(
            "44444444444444444444444444444444",
            crate::Scenario::Healthy,
            1_800_000_000,
        )
        .unwrap();
    let authority = service.authority_reader().current_identity().unwrap();
    let lease = service.dispatch_next(1_800_000_001, &authority).unwrap();
    let specification = service
        .provisioning_specification(&lease, 1_800_000_001)
        .unwrap();
    let connection = rusqlite::Connection::open(fixture_root.join("sandbox.sqlite3")).unwrap();
    connection
        .execute(
            concat!(
                "UPDATE runs SET provisioning_closed = 1, execution_state = 'service_failed', ",
                "namespace_uid = 'namespace-uid', runner_revoked = 1, ",
                "runner_process_absent = 1, journal_handoff = 1, runner_state_retiring = 1, ",
                "runner_state_retired = 1 WHERE run_id = ?1"
            ),
            [&admission.run_id],
        )
        .unwrap();
    connection
        .execute(
            concat!(
                "UPDATE cleanup_records SET eligible = 1, resource_state = 'owned', ",
                "namespace_uid = 'namespace-uid' WHERE run_id = ?1"
            ),
            [&admission.run_id],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO provisioned_object_owners VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                "namespace-uid",
                admission.run_id,
                format!("Namespace/sandbox-{}", admission.run_id),
                specification.cleanup_identity
            ],
        )
        .unwrap();
    (fixture_root, service, admission.run_id)
}

pub(crate) fn remove_root(root: &Path) {
    let generations = root.join("fixed-authority/generations");
    if let Ok(entries) = fs::read_dir(generations) {
        for entry in entries.flatten() {
            let _ = fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o700));
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[allow(
    clippy::similar_names,
    reason = "the fixed test controller and staging identities mirror production configuration"
)]
pub(crate) fn configuration(parent: &Path, digest_key: [u8; 32]) -> AuthorityConfiguration {
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    let staging_uid = if uid == 65_532 { 65_531 } else { 65_532 };
    let staging_gid = if gid == 65_532 { 65_531 } else { 65_532 };
    AuthorityConfiguration::new(root(parent, digest_key), uid, gid, staging_uid, staging_gid)
}
