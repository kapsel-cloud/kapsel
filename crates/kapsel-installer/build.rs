//! Fixed opt-in embedded bundle generation for the Kapsel installer.

#![allow(
    clippy::print_stdout,
    reason = "Cargo build-script directives are emitted on stdout"
)]

use std::{
    collections::BTreeMap,
    env,
    fmt::Write as _,
    fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
    process::ExitCode,
};
#[cfg(target_os = "linux")]
use std::{collections::BTreeSet, io::Read as _, mem::MaybeUninit, os::fd::OwnedFd};

#[cfg(target_os = "linux")]
use rustix::fs::{self as rfs, FileType, Mode, OFlags, RawDir, Stat, CWD};
use sha2::{Digest as _, Sha256};

const STAGE_ENV: &str = "KAPSEL_INSTALLER_STAGE";
const TEST_CRASH_SEAMS_ENV: &str = "KAPSEL_INSTALLER_TEST_CRASH_SEAMS";
const TARGET: &str = "x86_64-unknown-linux-gnu";
const BUNDLE_BYTES_MAX: u64 = 64 * 1024 * 1024;
const BINARY_BYTES_MAX: u64 = 32 * 1024 * 1024;
const STATIC_BYTES_MAX: u64 = 1024 * 1024;
const METADATA_BYTES_MAX: u64 = 64 * 1024;
#[cfg(target_os = "linux")]
const DIRECTORY_MODE: u32 = 0o755;

#[derive(Clone, Copy)]
enum Owner {
    Evidence,
    Root,
}

#[allow(
    dead_code,
    reason = "per-asset read bounds are consumed only by the Linux release-stage path"
)]
struct AssetSpec {
    name: &'static str,
    stage_path: &'static str,
    source_path: Option<&'static str>,
    destination: Option<&'static str>,
    mode: u32,
    owner: Owner,
    maximum: u64,
    executable: bool,
    metadata: bool,
}

const ASSETS: &[AssetSpec] = &[
    AssetSpec {
        name: "kapsel",
        stage_path: "usr/bin/kapsel",
        source_path: None,
        destination: Some("/usr/bin/kapsel"),
        mode: 0o755,
        owner: Owner::Root,
        maximum: BINARY_BYTES_MAX,
        executable: true,
        metadata: false,
    },
    AssetSpec {
        name: "kapsel-service-client",
        stage_path: "usr/bin/kapsel-service-client",
        source_path: None,
        destination: Some("/usr/bin/kapsel-service-client"),
        mode: 0o755,
        owner: Owner::Root,
        maximum: BINARY_BYTES_MAX,
        executable: true,
        metadata: false,
    },
    AssetSpec {
        name: "kapseld",
        stage_path: "usr/libexec/kapsel/kapseld",
        source_path: None,
        destination: Some("/usr/libexec/kapsel/kapseld"),
        mode: 0o755,
        owner: Owner::Root,
        maximum: BINARY_BYTES_MAX,
        executable: true,
        metadata: false,
    },
    AssetSpec {
        name: "kapseld.service",
        stage_path: "usr/lib/systemd/system/kapseld.service",
        source_path: Some("crates/kapseld/deploy/kapseld.service"),
        destination: Some("/usr/lib/systemd/system/kapseld.service"),
        mode: 0o644,
        owner: Owner::Root,
        maximum: STATIC_BYTES_MAX,
        executable: false,
        metadata: false,
    },
    AssetSpec {
        name: "kapseld.conf",
        stage_path: "usr/lib/sysusers.d/kapseld.conf",
        source_path: Some("crates/kapseld/deploy/kapseld.conf"),
        destination: Some("/usr/lib/sysusers.d/kapseld.conf"),
        mode: 0o644,
        owner: Owner::Root,
        maximum: STATIC_BYTES_MAX,
        executable: false,
        metadata: false,
    },
    AssetSpec {
        name: "kapseld-rbac.yaml",
        stage_path: "usr/share/kapsel/kapseld-rbac.yaml",
        source_path: Some("crates/kapseld/deploy/kapseld-rbac.yaml"),
        destination: Some("/usr/share/kapsel/kapseld-rbac.yaml"),
        mode: 0o644,
        owner: Owner::Root,
        maximum: STATIC_BYTES_MAX,
        executable: false,
        metadata: false,
    },
    AssetSpec {
        name: "KAPSEL_SERVICE_OPERATOR.md",
        stage_path: "usr/share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md",
        source_path: Some("docs/KAPSEL_SERVICE_OPERATOR.md"),
        destination: Some("/usr/share/doc/kapsel/KAPSEL_SERVICE_OPERATOR.md"),
        mode: 0o644,
        owner: Owner::Root,
        maximum: STATIC_BYTES_MAX,
        executable: false,
        metadata: false,
    },
    AssetSpec {
        name: "LICENSE",
        stage_path: "LICENSE",
        source_path: Some("LICENSE"),
        destination: None,
        mode: 0o644,
        owner: Owner::Evidence,
        maximum: STATIC_BYTES_MAX,
        executable: false,
        metadata: false,
    },
    AssetSpec {
        name: "KAPSEL-SERVICE-METADATA.json",
        stage_path: "KAPSEL-SERVICE-METADATA.json",
        source_path: None,
        destination: None,
        mode: 0o644,
        owner: Owner::Evidence,
        maximum: METADATA_BYTES_MAX,
        executable: false,
        metadata: true,
    },
];

fn main() -> ExitCode {
    println!("cargo:rustc-check-cfg=cfg(kapsel_installer_test_crash_seams)");
    println!("cargo:rerun-if-env-changed={TEST_CRASH_SEAMS_ENV}");
    if env::var(TEST_CRASH_SEAMS_ENV).as_deref() == Ok("1") {
        println!("cargo:rustc-cfg=kapsel_installer_test_crash_seams");
    }
    match generate_bundle() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(
                io::stderr().lock(),
                "Kapsel installer bundle failed: {error}"
            );
            ExitCode::FAILURE
        },
    }
}

fn generate_bundle() -> Result<(), String> {
    println!("cargo:rerun-if-env-changed={STAGE_ENV}");
    println!("cargo:rerun-if-changed=build.rs");
    let output = required_path("OUT_DIR")?;
    let generated = output.join("bundle.rs");
    let Some(stage) = env::var_os(STAGE_ENV) else {
        return fs::write(
            generated,
            concat!(
                "pub(super) const AVAILABLE: bool = false;\n",
                "pub(super) const BUNDLE_BYTES_MAX: usize = 0;\n",
                "pub(super) const EXPECTED: &[super::ExpectedAsset] = &[];\n",
                "pub(super) const ASSETS: &[super::Asset] = &[];\n",
            ),
        )
        .map_err(|error| format!("cannot generate unavailable bundle: {error}"));
    };

    if env::var("PROFILE").map_err(|_| String::from("missing Cargo profile"))? != "release" {
        return Err(String::from("embedded bundle requires the release profile"));
    }
    if env::var("TARGET").map_err(|_| String::from("missing Cargo target"))? != TARGET {
        return Err(format!("release bundle requires target {TARGET}"));
    }
    let stage = PathBuf::from(stage);
    if !stage.is_absolute() {
        return Err(String::from("release stage must be absolute"));
    }
    println!("cargo:rerun-if-changed={}", stage.display());
    let staged = read_exact_stage(&stage)?;
    let repository = repository_root()?;
    let mut generated_source = format!(
        concat!(
            "pub(super) const AVAILABLE: bool = true;\n",
            "pub(super) const BUNDLE_BYTES_MAX: usize = {};\n",
            "pub(super) const EXPECTED: &[super::ExpectedAsset] = &[\n"
        ),
        BUNDLE_BYTES_MAX
    );
    for asset in ASSETS {
        append_expected_asset(&mut generated_source, asset);
    }
    generated_source.push_str("];\n");
    generated_source.push_str("pub(super) const ASSETS: &[super::Asset] = &[\n");
    let mut total = 0_u64;

    for (index, asset) in ASSETS.iter().enumerate() {
        let bytes = staged
            .get(asset.stage_path)
            .ok_or_else(|| format!("staged {} is missing", asset.name))?;
        if asset.executable {
            validate_x86_64_elf(bytes, asset.name)?;
        }
        if asset.metadata
            && !serde_json::from_slice::<serde_json::Value>(bytes)
                .is_ok_and(|value| value.is_object())
        {
            return Err(String::from("installer metadata is not one JSON object"));
        }
        if let Some(source_path) = asset.source_path {
            let source = repository.join(source_path);
            println!("cargo:rerun-if-changed={}", source.display());
            let expected = fs::read(&source)
                .map_err(|error| format!("cannot read fixed source {source_path}: {error}"))?;
            if bytes != &expected {
                return Err(format!(
                    "staged {} differs from its fixed source",
                    asset.name
                ));
            }
        }
        total = total
            .checked_add(u64::try_from(bytes.len()).map_err(|_| String::from("asset too large"))?)
            .ok_or_else(|| String::from("bundle length overflow"))?;
        if total > BUNDLE_BYTES_MAX {
            return Err(String::from("embedded bundle exceeds 64 MiB"));
        }

        let copied = output.join(format!("asset-{index}"));
        fs::write(&copied, bytes)
            .map_err(|error| format!("cannot copy {} into Cargo output: {error}", asset.name))?;
        let digest = hex_digest(bytes);
        let _ = write!(
            generated_source,
            concat!(
                "    super::Asset {{ bytes: include_bytes!(concat!(env!(\"OUT_DIR\"), ",
                "\"/asset-{}\")), length: {}, sha256: {:?} }},\n"
            ),
            index,
            bytes.len(),
            digest,
        );
    }
    generated_source.push_str("];\n");
    fs::write(generated, generated_source)
        .map_err(|error| format!("cannot generate embedded bundle: {error}"))
}

fn append_expected_asset(output: &mut String, asset: &AssetSpec) {
    let destination = asset
        .destination
        .map_or_else(|| String::from("None"), |path| format!("Some({path:?})"));
    let mode = asset
        .destination
        .map_or_else(|| String::from("None"), |_| format!("Some({})", asset.mode));
    let owner = match asset.owner {
        Owner::Evidence => "super::OwnerClass::Evidence",
        Owner::Root => "super::OwnerClass::Root",
    };
    let _ = write!(
        output,
        concat!(
            "    super::ExpectedAsset {{ name: {:?}, destination: {}, ",
            "mode: {}, owner: {} }},\n"
        ),
        asset.name, destination, mode, owner
    );
}

fn required_path(name: &str) -> Result<PathBuf, String> {
    env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing Cargo {name}"))
}

fn repository_root() -> Result<PathBuf, String> {
    required_path("CARGO_MANIFEST_DIR")?
        .parent()
        .and_then(Path::parent)
        .map(Path::to_owned)
        .ok_or_else(|| String::from("installer crate is outside the workspace layout"))
}

#[cfg(target_os = "linux")]
fn expected_directories() -> BTreeSet<String> {
    let mut directories = BTreeSet::new();
    for asset in ASSETS {
        let mut parent = Path::new(asset.stage_path).parent();
        while let Some(path) = parent {
            if path.as_os_str().is_empty() {
                break;
            }
            if let Some(value) = path.to_str() {
                directories.insert(value.to_owned());
            }
            parent = path.parent();
        }
    }
    directories
}

#[cfg(not(target_os = "linux"))]
fn read_exact_stage(_: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    Err(String::from(
        "embedded bundle generation requires a Linux build host",
    ))
}

#[cfg(target_os = "linux")]
fn read_exact_stage(stage: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let directory = rfs::openat(
        CWD,
        stage,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("cannot open release stage: {error}"))?;
    validate_directory(&directory, "release stage")?;
    let expected_files = ASSETS
        .iter()
        .map(|asset| asset.stage_path.to_owned())
        .collect::<BTreeSet<String>>();
    let expected_directories = expected_directories();
    let mut files = BTreeMap::new();
    let mut directories = BTreeSet::new();
    collect_stage(
        &directory,
        "",
        &expected_files,
        &expected_directories,
        &mut files,
        &mut directories,
    )?;
    if files.keys().cloned().collect::<BTreeSet<_>>() != expected_files
        || directories != expected_directories
    {
        return Err(String::from("release stage inventory is not exact"));
    }
    Ok(files)
}

#[cfg(target_os = "linux")]
fn collect_stage(
    directory: &OwnedFd,
    prefix: &str,
    expected_files: &BTreeSet<String>,
    expected_directories: &BTreeSet<String>,
    files: &mut BTreeMap<String, Vec<u8>>,
    directories: &mut BTreeSet<String>,
) -> Result<(), String> {
    let before = rfs::fstat(directory)
        .map_err(|error| format!("cannot inspect release stage directory: {error}"))?;
    validate_directory_stat(&before, "release stage directory")?;
    let names = directory_names(directory)?;
    for name in names {
        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if expected_directories.contains(&relative) {
            let child = rfs::openat(
                directory,
                name.as_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| format!("cannot open staged directory {relative}: {error}"))?;
            validate_directory(&child, &relative)?;
            if !directories.insert(relative.clone()) {
                return Err(String::from("release stage directory repeated"));
            }
            collect_stage(
                &child,
                &relative,
                expected_files,
                expected_directories,
                files,
                directories,
            )?;
        } else if expected_files.contains(&relative) {
            let asset = ASSETS
                .iter()
                .find(|asset| asset.stage_path == relative)
                .ok_or_else(|| String::from("release stage asset specification is missing"))?;
            let bytes = read_stage_file(directory, &name, asset)?;
            if files.insert(relative, bytes).is_some() {
                return Err(String::from("release stage file repeated"));
            }
        } else {
            return Err(String::from("release stage contains an unknown entry"));
        }
    }
    let after = rfs::fstat(directory)
        .map_err(|error| format!("cannot re-inspect release stage directory: {error}"))?;
    if !stable_directory(&before, &after) {
        return Err(String::from("release stage directory changed while read"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn directory_names(directory: &OwnedFd) -> Result<Vec<String>, String> {
    let mut buffer = [MaybeUninit::uninit(); 8192];
    let mut entries = RawDir::new(directory, &mut buffer);
    let mut names = Vec::new();
    while let Some(entry) = entries.next() {
        let entry = entry.map_err(|error| format!("cannot enumerate release stage: {error}"))?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let name = std::str::from_utf8(bytes)
            .map_err(|_| String::from("release stage contains a non-UTF-8 name"))?;
        if name.is_empty() || name.contains('/') {
            return Err(String::from("release stage contains an invalid name"));
        }
        names.push(name.to_owned());
    }
    names.sort();
    Ok(names)
}

#[cfg(target_os = "linux")]
fn validate_directory(directory: &OwnedFd, label: &str) -> Result<(), String> {
    let metadata =
        rfs::fstat(directory).map_err(|error| format!("cannot inspect {label}: {error}"))?;
    validate_directory_stat(&metadata, label)
}

#[cfg(target_os = "linux")]
fn validate_directory_stat(metadata: &Stat, label: &str) -> Result<(), String> {
    if !FileType::from_raw_mode(metadata.st_mode).is_dir()
        || metadata.st_mode & 0o7777 != DIRECTORY_MODE
    {
        return Err(format!("{label} has invalid metadata"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn stable_directory(before: &Stat, after: &Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_nlink == after.st_nlink
        && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

#[cfg(target_os = "linux")]
fn read_stage_file(parent: &OwnedFd, name: &str, asset: &AssetSpec) -> Result<Vec<u8>, String> {
    let descriptor = rfs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("cannot open staged {}: {error}", asset.name))?;
    let before = rfs::fstat(&descriptor)
        .map_err(|error| format!("cannot inspect staged {}: {error}", asset.name))?;
    if !FileType::from_raw_mode(before.st_mode).is_file()
        || before.st_mode & 0o7777 != asset.mode
        || before.st_nlink != 1
        || before.st_size <= 0
        || u64::try_from(before.st_size).map_or(true, |length| length > asset.maximum)
    {
        return Err(format!("staged {} has invalid metadata", asset.name));
    }

    let mut file = fs::File::from(descriptor);
    let mut bytes = Vec::with_capacity(usize::try_from(before.st_size).unwrap_or(0));
    (&mut file)
        .take(asset.maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read staged {}: {error}", asset.name))?;
    let after = rfs::fstat(&file)
        .map_err(|error| format!("cannot re-inspect staged {}: {error}", asset.name))?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > asset.maximum)
        || !stable_file(&before, &after, bytes.len())
    {
        return Err(format!("staged {} changed while read", asset.name));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn stable_file(before: &Stat, after: &Stat, length: usize) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_nlink == after.st_nlink
        && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
        && usize::try_from(after.st_size) == Ok(length)
}

fn validate_x86_64_elf(bytes: &[u8], name: &str) -> Result<(), String> {
    let valid_header = bytes.len() >= 64
        && bytes[..4] == *b"\x7fELF"
        && bytes[4] == 2
        && bytes[5] == 1
        && bytes[6] == 1
        && matches!(little_u16(bytes, 16), Some(2 | 3))
        && little_u16(bytes, 18) == Some(62)
        && little_u32(bytes, 20) == Some(1)
        && little_u16(bytes, 52) == Some(64)
        && little_u16(bytes, 54) == Some(56);
    let Some(program_offset) = little_u64(bytes, 32).and_then(|value| usize::try_from(value).ok())
    else {
        return Err(format!("staged {name} is not an x86-64 ELF executable"));
    };
    let Some(program_count) = little_u16(bytes, 56).map(usize::from) else {
        return Err(format!("staged {name} is not an x86-64 ELF executable"));
    };
    let table_fits = program_count > 0
        && program_count
            .checked_mul(56)
            .and_then(|length| program_offset.checked_add(length))
            .is_some_and(|end| end <= bytes.len());
    if !valid_header || !table_fits {
        return Err(format!("staged {name} is not an x86-64 ELF executable"));
    }

    let mut executable_load = false;
    for index in 0..program_count {
        let offset = program_offset + index * 56;
        let file_offset =
            little_u64(bytes, offset + 8).and_then(|value| usize::try_from(value).ok());
        let file_size =
            little_u64(bytes, offset + 32).and_then(|value| usize::try_from(value).ok());
        let memory_size = little_u64(bytes, offset + 40);
        let segment_fits = file_offset
            .zip(file_size)
            .and_then(|(start, length)| start.checked_add(length))
            .is_some_and(|end| end <= bytes.len());
        if !segment_fits
            || memory_size
                .zip(little_u64(bytes, offset + 32))
                .is_none_or(|(memory, file)| memory < file)
        {
            return Err(format!("staged {name} has an invalid ELF program header"));
        }
        if little_u32(bytes, offset) == Some(1)
            && little_u32(bytes, offset + 4).is_some_and(|flags| flags & 1 == 1)
        {
            executable_load = true;
        }
    }
    if !executable_load {
        return Err(format!("staged {name} has no executable load segment"));
    }
    Ok(())
}

fn little_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset.checked_add(2)?)?
        .try_into()
        .ok()
        .map(u16::from_le_bytes)
}

fn little_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

fn little_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes
        .get(offset..offset.checked_add(8)?)?
        .try_into()
        .ok()
        .map(u64::from_le_bytes)
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}
