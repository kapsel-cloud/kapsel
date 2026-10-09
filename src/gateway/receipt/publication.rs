//! Receipt byte identity and feature-gated service process checkpoints.

use sha2::{Digest, Sha256};

pub(crate) fn receipt_digest_hex(receipt: &[u8]) -> String {
    let digest = Sha256::digest(receipt);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(hex_digit(byte >> 4));
        output.push(hex_digit(byte & 0x0f));
    }
    output
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        10..=15 => char::from(b'a' + value - 10),
        _ => '?',
    }
}

#[cfg(feature = "demo-harness")]
pub(in crate::gateway) use checkpoints::create_private_file;
pub(crate) use checkpoints::validate_private_directory;

mod checkpoints {
    #[cfg(feature = "demo-harness")]
    use std::io::Write as _;
    use std::{
        ffi::{OsStr, OsString},
        fs::File,
        io,
        os::unix::fs::MetadataExt as _,
        path::{Component, Path, PathBuf},
    };

    #[cfg(feature = "demo-harness")]
    use rustix::fs::{fchmod, fstat, statat, AtFlags};
    use rustix::fs::{openat, Mode, OFlags, CWD};

    pub(crate) fn validate_private_directory(path: &Path) -> io::Result<()> {
        open_parent(&path.join(".kap0038-directory-check")).map(|_| ())
    }

    #[cfg(feature = "demo-harness")]
    pub(in crate::gateway) fn create_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
        let (directory, name) = open_parent(path)?;

        let mode = Mode::RUSR | Mode::WUSR;
        let mut file = File::from(openat(
            &directory,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            mode,
        )?);

        fchmod(&file, mode)?;
        let metadata = file.metadata()?;
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o600
            || !metadata.is_file()
        {
            return Err(io::Error::other("unsafe checkpoint file"));
        }

        file.write_all(bytes)?;
        file.sync_all()?;

        let descriptor = fstat(&file)?;
        let named = statat(&directory, &name, AtFlags::SYMLINK_NOFOLLOW)?;
        if descriptor.st_dev != named.st_dev || descriptor.st_ino != named.st_ino {
            return Err(io::Error::other("checkpoint identity changed"));
        }

        directory.sync_all()
    }

    fn open_parent(path: &Path) -> io::Result<(File, OsString)> {
        let mut names = Vec::new();
        let mut absolute = false;
        for component in path.components() {
            match component {
                Component::RootDir => absolute = true,
                Component::CurDir => {},
                Component::Normal(name) => names.push(name.to_os_string()),
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(io::Error::other("unsafe checkpoint path"));
                },
            }
        }

        let destination = names
            .pop()
            .ok_or_else(|| io::Error::other("missing name"))?;
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        let descriptor_root = descriptor_root(&names, absolute)?;
        let (mut directory, consumed) = if let Some(root) = descriptor_root {
            (File::from(openat(CWD, &root, flags, Mode::empty())?), 4)
        } else {
            let start = if absolute {
                OsStr::new("/")
            } else {
                OsStr::new(".")
            };
            (
                File::from(openat(CWD, start, flags | OFlags::NOFOLLOW, Mode::empty())?),
                0,
            )
        };

        for name in names.into_iter().skip(consumed) {
            directory = File::from(openat(
                &directory,
                name,
                flags | OFlags::NOFOLLOW,
                Mode::empty(),
            )?);
        }

        let metadata = directory.metadata()?;
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(io::Error::other("unsafe checkpoint directory"));
        }
        Ok((directory, destination))
    }

    fn descriptor_root(names: &[OsString], absolute: bool) -> io::Result<Option<PathBuf>> {
        if !absolute
            || names.len() < 4
            || names[0] != "proc"
            || names[1] != "self"
            || names[2] != "fd"
        {
            return Ok(None);
        }
        let descriptor = names[3]
            .to_str()
            .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
            .ok_or_else(|| io::Error::other("invalid checkpoint descriptor"))?;
        Ok(Some(Path::new("/proc/self/fd").join(descriptor)))
    }
}
