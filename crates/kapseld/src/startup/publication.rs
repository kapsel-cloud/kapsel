//! Operator-only cold publication. Filesystem authority stays in retained installation roots.

use std::{
    fs::File,
    io::{self, Read as _, Write as _},
    path::Path,
    process::ExitCode,
    sync::atomic::{AtomicU64, Ordering},
};

use rustix::fs::{openat, renameat, unlinkat, AtFlags, Mode, OFlags};

use super::{
    descriptor_directory_path, require_private_identity, validate_optional_private_file,
    InstallationRoots, JOURNAL_BYTES_MAX, OPERATOR_DOCUMENT_BYTES_MAX,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    Published,
    NotPublished,
    Indeterminate,
}

impl Outcome {
    fn status(self) -> (&'static [u8], u8) {
        match self {
            Self::Published => (b"PUBLISHED\n", 0),
            Self::NotPublished => (b"NOT_PUBLISHED\n", 4),
            Self::Indeterminate => (b"INDETERMINATE\n", 5),
        }
    }
}

pub(crate) fn replace_operator_config(root: &Path) -> ExitCode {
    let outcome = replace(root, &mut io::stdin().lock());
    let (line, exit) = outcome.status();
    let mut output = io::stdout().lock();
    if output
        .write_all(line)
        .and_then(|()| output.flush())
        .is_err()
    {
        return ExitCode::from(5);
    }
    ExitCode::from(exit)
}

fn replace(root: &Path, input: &mut impl io::Read) -> Outcome {
    let Ok(roots) = InstallationRoots::open_at(root) else {
        return Outcome::NotPublished;
    };
    #[cfg(feature = "test-harness")]
    let _ = std::fs::write(root.join("control/publisher.ready"), b"");
    let Ok(bytes) = validate(&roots, input) else {
        return Outcome::NotPublished;
    };
    publish(&roots.configuration, &bytes)
}

fn validate(roots: &InstallationRoots, input: &mut impl io::Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(OPERATOR_DOCUMENT_BYTES_MAX + 1);
    input
        .take((OPERATOR_DOCUMENT_BYTES_MAX + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > OPERATOR_DOCUMENT_BYTES_MAX {
        return Err(io::Error::other("candidate exceeds bound"));
    }
    validate_optional_private_file(&roots.state, "journal.sqlite3", JOURNAL_BYTES_MAX)?;
    validate_optional_private_file(&roots.state, "journal.sqlite3.kap0038-worker.lock", 0)?;
    let path = descriptor_directory_path(&roots.state)?.join("journal.sqlite3");
    let document = kapsel::parse_service_operator_document(&bytes, path)
        .map_err(|_| io::Error::other("invalid candidate"))?;
    kapsel::ServiceApplication::validate_replacement(&document.configuration)
        .map_err(|_| io::Error::other("invalid replacement"))?;
    Ok(bytes)
}

struct Temporary<'a> {
    directory: &'a File,
    name: String,
    file: File,
}

impl<'a> Temporary<'a> {
    fn create(directory: &'a File) -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let name = format!(
            ".operator-{}-{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let file = File::from(openat(
            directory,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?);
        let temporary = Self {
            directory,
            name,
            file,
        };
        require_private_identity(directory, &temporary.name, &temporary.file, 0)?;
        Ok(temporary)
    }
}

impl Drop for Temporary<'_> {
    fn drop(&mut self) {
        if require_private_identity(
            self.directory,
            &self.name,
            &self.file,
            OPERATOR_DOCUMENT_BYTES_MAX as u64,
        )
        .is_ok()
        {
            let _ = unlinkat(self.directory, self.name.as_str(), AtFlags::empty());
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    None,
    Write,
    FileSync,
    BeforeRename,
    Rename,
    DirectorySync,
}

fn publish(directory: &File, bytes: &[u8]) -> Outcome {
    publish_candidate(
        directory,
        bytes,
        #[cfg(test)]
        Fault::None,
    )
}

fn publish_candidate(directory: &File, bytes: &[u8], #[cfg(test)] fault: Fault) -> Outcome {
    let Ok(mut temporary) = Temporary::create(directory) else {
        return Outcome::NotPublished;
    };
    #[cfg(test)]
    if fault == Fault::Write {
        return Outcome::NotPublished;
    }
    if temporary.file.write_all(bytes).is_err() {
        return Outcome::NotPublished;
    }
    #[cfg(test)]
    if fault == Fault::FileSync {
        return Outcome::NotPublished;
    }
    if temporary.file.sync_all().is_err()
        || require_private_identity(
            directory,
            &temporary.name,
            &temporary.file,
            OPERATOR_DOCUMENT_BYTES_MAX as u64,
        )
        .is_err()
        || validate_optional_private_file(
            directory,
            "operator.json",
            OPERATOR_DOCUMENT_BYTES_MAX as u64,
        )
        .is_err()
    {
        return Outcome::NotPublished;
    }
    #[cfg(test)]
    if fault == Fault::BeforeRename {
        return Outcome::NotPublished;
    }
    // An error returned by rename does not prove that publication did not occur.
    #[cfg(test)]
    if fault == Fault::Rename {
        // Force a real rename syscall failure after the final checks, not a substitute outcome.
        assert!(unlinkat(directory, temporary.name.as_str(), AtFlags::empty()).is_ok());
    }
    if renameat(
        directory,
        temporary.name.as_str(),
        directory,
        "operator.json",
    )
    .is_err()
    {
        return Outcome::Indeterminate;
    }
    #[cfg(test)]
    if fault == Fault::DirectorySync {
        return Outcome::Indeterminate;
    }
    if directory.sync_all().is_err() {
        return Outcome::Indeterminate;
    }
    Outcome::Published
}

#[cfg(test)]
#[path = "publication_tests.rs"]
mod tests;
