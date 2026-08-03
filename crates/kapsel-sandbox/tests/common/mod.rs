use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use kapsel_sandbox::AuthorityConfiguration;
use serde::Serialize;
use sha2::{Digest, Sha256};

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

fn hex(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02x}").unwrap();
            output
        },
    )
}

fn directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

pub(crate) fn authority_root(parent: &Path, digest_key: [u8; 32]) -> PathBuf {
    let root = parent.join("fixed-authority");
    if root.exists() {
        return root;
    }
    directory(&root);
    directory(&root.join("incoming"));
    directory(&root.join("generations"));
    directory(&root.join("dispatch"));
    let generation = root.join("generations/generation-00000000000000000001");
    directory(&generation);
    let mut files = Vec::new();
    for name in NAMES {
        let payload = if name == "tombstone-digest-key" {
            digest_key.to_vec()
        } else {
            vec![1]
        };
        fs::write(generation.join(name), &payload).unwrap();
        fs::set_permissions(generation.join(name), fs::Permissions::from_mode(0o400)).unwrap();
        files.push(ManifestFile {
            name,
            length: u64::try_from(payload.len()).unwrap(),
            sha256: hex(Sha256::digest(&payload)),
        });
    }
    let manifest = serde_json::to_vec(&Manifest {
        version: 1,
        generation: 1,
        previous_generation: None,
        files,
    })
    .unwrap();
    let manifest_digest = hex(Sha256::digest(&manifest));
    fs::write(generation.join("manifest.json"), manifest).unwrap();
    fs::set_permissions(
        generation.join("manifest.json"),
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    fs::set_permissions(&generation, fs::Permissions::from_mode(0o500)).unwrap();
    fs::write(
        root.join("current"),
        serde_json::to_vec(&Current {
            version: 1,
            generation: 1,
            manifest_digest,
        })
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(root.join("current"), fs::Permissions::from_mode(0o400)).unwrap();
    root
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

pub(crate) fn authority_configuration(
    parent: &Path,
    digest_key: [u8; 32],
) -> AuthorityConfiguration {
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    AuthorityConfiguration::new(
        authority_root(parent, digest_key),
        uid,
        gid,
        if uid == 65_532 { 65_531 } else { 65_532 },
        if gid == 65_532 { 65_531 } else { 65_532 },
    )
}

pub(crate) fn authority_arguments(parent: &Path) -> Vec<String> {
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    vec![
        "--authority-root".into(),
        parent.join("fixed-authority").display().to_string(),
        "--controller-uid".into(),
        uid.to_string(),
        "--controller-gid".into(),
        gid.to_string(),
        "--staging-uid".into(),
        if uid == 65_532 { "65531" } else { "65532" }.into(),
        "--staging-gid".into(),
        if gid == 65_532 { "65531" } else { "65532" }.into(),
    ]
}
