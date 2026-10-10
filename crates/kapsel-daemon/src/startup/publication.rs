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
    let publication_outcome = replace(root, &mut io::stdin().lock());
    let (line, exit) = publication_outcome.status();
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

    let Ok(bytes) = validate_candidate(&roots, input) else {
        return Outcome::NotPublished;
    };

    publish(&roots.configuration, &bytes)
}

fn validate_candidate(roots: &InstallationRoots, input: &mut impl io::Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(OPERATOR_DOCUMENT_BYTES_MAX + 1);
    input
        .take((OPERATOR_DOCUMENT_BYTES_MAX + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > OPERATOR_DOCUMENT_BYTES_MAX {
        return Err(io::Error::other("candidate exceeds bound"));
    }

    validate_optional_private_file(&roots.state, "journal.sqlite3", JOURNAL_BYTES_MAX)?;
    validate_optional_private_file(&roots.state, "journal.sqlite3.kap0038-worker.lock", 0)?;

    let journal_path = descriptor_directory_path(&roots.state)?.join("journal.sqlite3");
    let document = kapsel::parse_service_operator_document(&bytes, journal_path)
        .map_err(|_| io::Error::other("invalid candidate"))?;
    kapsel::ServiceApplication::validate_replacement(&document.configuration)
        .map_err(|_| io::Error::other("invalid replacement"))?;
    Ok(bytes)
}

struct TemporaryCandidate<'a> {
    directory: &'a File,
    name: String,
    file: File,
}

impl<'a> TemporaryCandidate<'a> {
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

impl Drop for TemporaryCandidate<'_> {
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
    let Ok(mut temporary) = TemporaryCandidate::create(directory) else {
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
mod tests {
    //! Cold publisher refusal, exact bytes and owned temporary-file fault evidence.
    #![allow(
        clippy::panic,
        reason = "authority consumption must fail the contention fixture"
    )]
    use std::{fs, os::unix::fs::PermissionsExt as _};

    use super::*;
    use crate::startup::{tests::valid_root, InstallationInputs};

    #[test]
    fn invalid_candidate_leaves_operator_and_journal_exactly_unchanged() {
        let root = valid_root("publisher-invalid");
        let inputs = InstallationInputs::open_at(&root).unwrap();
        let mut execution = inputs.open_execution().unwrap();
        let action = execution
            .application
            .approved_actions(None)
            .unwrap()
            .remove(0);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(execution.application.select(
                "service-op",
                kapsel::ServiceExecution {
                    git_receiver: None,
                    kubernetes_client: None,
                    receipt_signing: None,
                },
                |_| {},
            ))
            .unwrap();
        drop(execution);
        drop(inputs);
        let path = root.join("etc/kapsel/operator.json");
        let original = fs::read(&path).unwrap();
        let journal = root.join("var/lib/kapsel/journal.sqlite3");
        let history = fs::read(&journal).unwrap();
        let kapsel::ApprovedAction::Kubernetes {
            request,
            approved_target,
            ..
        } = action
        else {
            panic!("expected the Kubernetes fixture approval");
        };
        let conflicting_grant = kapsel::provision_exact_grant(&kapsel::GrantProvisioning {
            authorization: &kapsel::ExactAuthorization {
                authorization_id: "different-authority".into(),
                operation_id: request.operation_id,
                namespace: request.namespace,
                deployment: request.deployment,
                container: request.container,
                immutable_image_digest: request.immutable_image_digest,
                approved_target: Some(approved_target),
            },
            signing_seed: &[101; 32],
            signing_key_id: "service-owner-key",
        })
        .unwrap();
        let mut conflict: serde_json::Value = serde_json::from_slice(&original).unwrap();
        conflict["approvals"][0]["signed_grant_hex"] =
            crate::startup::tests::hex(&conflicting_grant).into();
        for bytes in [
            b"invalid".to_vec(),
            vec![b' '; OPERATOR_DOCUMENT_BYTES_MAX + 1],
            serde_json::to_vec(&conflict).unwrap(),
        ] {
            assert_eq!(replace(&root, &mut bytes.as_slice()), Outcome::NotPublished);
            assert_eq!(fs::read(&path).unwrap(), original);
            assert_eq!(fs::read(&journal).unwrap(), history);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn publication_faults_have_honest_outcomes_and_only_remove_owned_temporary() {
        for fault in [
            Fault::None,
            Fault::Write,
            Fault::FileSync,
            Fault::BeforeRename,
            Fault::Rename,
            Fault::DirectorySync,
        ] {
            let root = valid_root(&format!("publisher-fault-{fault:?}"));
            let roots = InstallationRoots::open_at(&root).unwrap();
            let path = root.join("etc/kapsel/operator.json");
            let original = fs::read(&path).unwrap();
            let mut candidate = original.clone();
            candidate.extend_from_slice(b" \n");
            let stale = root.join("etc/kapsel/.operator-stale.tmp");
            fs::write(&stale, b"not ours").unwrap();

            let result = publish_candidate(&roots.configuration, &candidate, fault);

            let renamed = matches!(fault, Fault::None | Fault::DirectorySync);
            assert_eq!(
                result,
                match fault {
                    Fault::None => Outcome::Published,
                    Fault::Rename | Fault::DirectorySync => Outcome::Indeterminate,
                    _ => Outcome::NotPublished,
                }
            );
            assert_eq!(
                fs::read(&path).unwrap(),
                if renamed { candidate } else { original }
            );
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
                0o600
            );
            assert_eq!(fs::read(&stale).unwrap(), b"not ours");
            assert_eq!(
                fs::read_dir(root.join("etc/kapsel"))
                    .unwrap()
                    .filter(|entry| entry
                        .as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .ends_with(".tmp"))
                    .count(),
                1
            );

            drop(roots);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn publication_stays_on_retained_configuration_directory() {
        let root = valid_root("publisher-retained-root");
        let roots = InstallationRoots::open_at(&root).unwrap();
        let configuration = root.join("etc/kapsel");
        let retained = root.join("etc/kapsel.retained");
        let mut candidate = fs::read(configuration.join("operator.json")).unwrap();
        candidate.push(b'\n');
        fs::rename(&configuration, &retained).unwrap();
        fs::create_dir(&configuration).unwrap();
        fs::set_permissions(&configuration, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(configuration.join("operator.json"), b"foreign root").unwrap();
        assert_eq!(
            validate_candidate(&roots, &mut candidate.as_slice()).unwrap(),
            candidate
        );
        assert_eq!(
            publish(&roots.configuration, &candidate),
            Outcome::Published
        );
        assert_eq!(fs::read(retained.join("operator.json")).unwrap(), candidate);
        assert_eq!(
            fs::read(configuration.join("operator.json")).unwrap(),
            b"foreign root"
        );
        drop(roots);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn publication_does_not_unlink_a_substituted_temporary_inode() {
        let root = valid_root("publisher-temp-substitution");
        let roots = InstallationRoots::open_at(&root).unwrap();
        let temp = TemporaryCandidate::create(&roots.configuration).unwrap();
        let path = root.join("etc/kapsel").join(&temp.name);
        fs::rename(&path, path.with_extension("retained")).unwrap();
        fs::write(&path, b"replacement").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        drop(temp);
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        drop(roots);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn lifecycle_contention_precedes_candidate_consumption_and_exact_publication() {
        struct Unread;
        impl io::Read for Unread {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("contending publisher consumed authority");
            }
        }
        let root = valid_root("publisher-contention");
        let inputs = InstallationInputs::open_at(&root).unwrap();
        assert_eq!(replace(&root, &mut Unread), Outcome::NotPublished);
        assert!(InstallationInputs::open_at(&root).is_err());
        drop(inputs);
        let path = root.join("etc/kapsel/operator.json");
        let mut bytes = fs::read(&path).unwrap();
        bytes.extend_from_slice(b"\n \t");
        assert_eq!(replace(&root, &mut bytes.as_slice()), Outcome::Published);
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(!root.join("var/lib/kapsel/journal.sqlite3").exists());
        fs::remove_dir_all(root).unwrap();
    }
}
