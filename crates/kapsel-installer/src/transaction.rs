//! Portable transaction validation and recovery-state transition rules.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InstallPhase {
    Blocked,
    Prepared,
    Installing,
    RollingBack,
    RolledBack,
}

pub(super) fn classify_install_phase(
    phase: TransactionPhase,
) -> Result<InstallPhase, InstallerError> {
    match phase {
        TransactionPhase::IdentityBlocked => Ok(InstallPhase::Blocked),
        TransactionPhase::Prepared => Ok(InstallPhase::Prepared),
        TransactionPhase::Installing => Ok(InstallPhase::Installing),
        TransactionPhase::RollingBack => Ok(InstallPhase::RollingBack),
        TransactionPhase::RolledBack => Ok(InstallPhase::RolledBack),
        _ => Err(InstallerError::TransactionFailure),
    }
}

pub(super) const TRANSACTION_BYTES_MAX: usize = 64 * 1024;
pub(super) fn matches_stable_identity(
    transaction: &InstallerTransaction,
    expected: &InstallerTransaction,
) -> bool {
    transaction.cluster == expected.cluster
        && transaction.input_directory == expected.input_directory
        && transaction.installer_sha256 == expected.installer_sha256
        && transaction.kube_context == expected.kube_context
        && transaction.operator_inputs == expected.operator_inputs
        && transaction.schema == expected.schema
}

pub(super) fn encode_transaction(
    transaction: &InstallerTransaction,
) -> Result<Vec<u8>, InstallerError> {
    validate_transaction(transaction)?;
    let bytes = serde_json::to_vec(transaction).map_err(|_| InstallerError::TransactionFailure)?;
    if bytes.len() > TRANSACTION_BYTES_MAX {
        return Err(InstallerError::TransactionFailure);
    }
    Ok(bytes)
}

pub(super) fn decode_transaction(bytes: &[u8]) -> Result<InstallerTransaction, InstallerError> {
    if bytes.len() > TRANSACTION_BYTES_MAX {
        return Err(InstallerError::TransactionFailure);
    }
    let transaction = serde_json::from_slice::<InstallerTransaction>(bytes)
        .map_err(|_| InstallerError::TransactionFailure)?;
    validate_transaction(&transaction)?;
    if serde_json::to_vec(&transaction).map_err(|_| InstallerError::TransactionFailure)? != bytes {
        return Err(InstallerError::TransactionFailure);
    }
    Ok(transaction)
}

pub(super) fn validate_initial_transaction(
    transaction: &InstallerTransaction,
) -> Result<(), InstallerError> {
    validate_transaction(transaction)?;
    if transaction.action != Action::Install || transaction.phase != TransactionPhase::Prepared {
        return Err(InstallerError::TransactionFailure);
    }
    Ok(())
}

pub(super) fn validate_transaction(
    transaction: &InstallerTransaction,
) -> Result<(), InstallerError> {
    let digests = [
        transaction.bootstrap_kubeconfig_initial_sha256.as_str(),
        transaction.bootstrap_kubeconfig_sha256.as_str(),
        transaction.cluster.ca_sha256.as_str(),
        transaction.installer_sha256.as_str(),
        transaction.operator_inputs.authorization_pub.as_str(),
        transaction.operator_inputs.grant_bin.as_str(),
        transaction.operator_inputs.receipt_seed.as_str(),
        transaction.operator_inputs.receipt_trust.as_str(),
        transaction.transaction_id.as_str(),
    ];
    if transaction.schema != 1
        || transaction.credential_expiration.is_some()
        || !transaction.kubernetes_resources.is_empty()
        || !valid_action_phase(transaction.action, transaction.phase)
        || !valid_transaction_state(transaction)
        || transaction.input_directory.uid != 0
        || transaction.input_directory.mode != 0o700
        || !valid_transaction_path(&transaction.input_directory.path)
        || !valid_kubernetes_name(&transaction.kube_context)
        || validate_server(transaction.cluster.server.clone()).is_err()
        || digests.into_iter().any(|digest| !valid_digest(digest))
    {
        return Err(InstallerError::TransactionFailure);
    }
    Ok(())
}

pub(super) fn valid_transaction_state(transaction: &InstallerTransaction) -> bool {
    let resources = transaction.host_resources.as_slice();
    let identity_count = resources
        .iter()
        .take_while(|resource| !matches!(resource, HostResource::File(_)))
        .count();
    let identities = &resources[..identity_count];
    let files = &resources[identity_count..];
    let valid_identities = match identities {
        [] => true,
        [HostResource::Group(first)] => valid_group(first, "kapsel"),
        [HostResource::Group(first), HostResource::Group(second)] => {
            valid_group(first, "kapsel")
                && valid_group(second, "kapsel-service-callers")
                && first.gid != second.gid
        },
        [HostResource::Group(first), HostResource::Group(second), HostResource::User(user)] => {
            valid_group(first, "kapsel")
                && valid_group(second, "kapsel-service-callers")
                && first.gid != second.gid
                && valid_user(user, "kapsel", first.gid, "/var/lib/kapsel", transaction)
        },
        [first, second, service, caller] => {
            valid_complete_identities(first, second, service, caller, transaction)
        },
        _ => false,
    };
    let valid_files = identities.len() == 4
        && files
            .iter()
            .enumerate()
            .all(|(index, resource)| match resource {
                HostResource::File(file) => valid_host_file(file, &files[..index]),
                HostResource::Group(_) | HostResource::User(_) => false,
            });
    if !valid_identities || !files.is_empty() && !valid_files {
        return false;
    }
    let group_count = identities
        .iter()
        .take_while(|resource| matches!(resource, HostResource::Group(_)))
        .count();
    let user_resources_empty = group_count == identities.len();
    valid_transaction_phase_state(
        transaction,
        resources,
        transaction.pending.as_ref(),
        group_count,
        user_resources_empty,
    )
}

pub(super) fn valid_transaction_phase_state(
    transaction: &InstallerTransaction,
    resources: &[HostResource],
    pending: Option<&PendingAction>,
    group_count: usize,
    user_resources_empty: bool,
) -> bool {
    match transaction.phase {
        TransactionPhase::Prepared | TransactionPhase::RolledBack => {
            resources.is_empty() && pending.is_none()
        },
        TransactionPhase::Installing => match pending {
            None => true,
            Some(PendingAction::CreateGroup {
                gid,
                name,
                transaction_id,
            }) => {
                user_resources_empty
                    && valid_pending_group(
                        &resources[..group_count],
                        *gid,
                        name,
                        transaction_id,
                        transaction,
                    )
            },
            Some(PendingAction::CreateUser {
                gecos_transaction_id,
                home,
                locked,
                name,
                primary_gid,
                shell,
                uid,
            }) => valid_pending_user(
                resources,
                *uid,
                *primary_gid,
                name,
                gecos_transaction_id,
                home,
                shell,
                *locked,
                transaction,
            ),
            Some(stage @ PendingAction::StageHost { .. }) => {
                resources.len() >= 4 && valid_stage_host(stage, resources, transaction)
            },
            Some(publish @ PendingAction::PublishHost { .. }) => {
                resources.len() >= 4 && valid_publish_host(publish, resources, transaction)
            },
            Some(PendingAction::RemoveGroup { .. }) => false,
        },
        TransactionPhase::IdentityBlocked => {
            resources.len() >= 2
                && match pending {
                    None => true,
                    Some(PendingAction::CreateUser {
                        gecos_transaction_id,
                        home,
                        locked,
                        name,
                        primary_gid,
                        shell,
                        uid,
                    }) => valid_pending_user(
                        resources,
                        *uid,
                        *primary_gid,
                        name,
                        gecos_transaction_id,
                        home,
                        shell,
                        *locked,
                        transaction,
                    ),
                    _ => false,
                }
        },
        TransactionPhase::RollingBack => match pending {
            None => user_resources_empty,
            Some(PendingAction::RemoveGroup { group }) => {
                user_resources_empty
                    && resources
                        .last()
                        .is_some_and(|resource| resource == &HostResource::Group(group.clone()))
            },
            _ => false,
        },
        _ => pending.is_none(),
    }
}

pub(super) fn valid_complete_identities(
    first: &HostResource,
    second: &HostResource,
    service: &HostResource,
    caller: &HostResource,
    transaction: &InstallerTransaction,
) -> bool {
    let HostResource::Group(first) = first else {
        return false;
    };
    let HostResource::Group(second) = second else {
        return false;
    };
    let HostResource::User(service) = service else {
        return false;
    };
    let HostResource::User(caller) = caller else {
        return false;
    };
    valid_group(first, "kapsel")
        && valid_group(second, "kapsel-service-callers")
        && first.gid != second.gid
        && valid_user(service, "kapsel", first.gid, "/var/lib/kapsel", transaction)
        && valid_user(
            caller,
            "kapsel-service-caller",
            second.gid,
            "/nonexistent",
            transaction,
        )
        && service.uid != caller.uid
}

pub(super) fn valid_group(resource: &GroupResource, name: &str) -> bool {
    resource.kind == GroupResourceKind::Group
        && resource.name == name
        && (101..=999).contains(&resource.gid)
}

pub(super) fn valid_user(
    resource: &UserResource,
    name: &str,
    primary_gid: u32,
    home: &str,
    transaction: &InstallerTransaction,
) -> bool {
    resource.kind == UserResourceKind::User
        && resource.name == name
        && (101..=999).contains(&resource.uid)
        && resource.primary_gid == primary_gid
        && resource.gecos_transaction_id == transaction.transaction_id
        && resource.home == home
        && resource.shell == "/usr/sbin/nologin"
        && resource.locked
}

const HOST_FILE_BYTES_MAX: u64 = 64 * 1024 * 1024;

pub(super) fn valid_host_file(resource: &FileResource, earlier: &[HostResource]) -> bool {
    resource.kind == FileResourceKind::File
        && resource.file_type == HostFileType::Regular
        && resource.device != 0
        && resource.inode != 0
        && resource.length > 0
        && resource.length <= HOST_FILE_BYTES_MAX
        && valid_host_mode(resource.mode)
        && valid_transaction_path(&resource.path)
        && resource.path != "/"
        && valid_digest(&resource.sha256)
        && earlier.iter().all(|item| match item {
            HostResource::File(file) => {
                file.path != resource.path
                    && (file.device != resource.device || file.inode != resource.inode)
            },
            HostResource::Group(_) | HostResource::User(_) => true,
        })
}

pub(super) fn valid_stage_host(
    pending: &PendingAction,
    resources: &[HostResource],
    transaction: &InstallerTransaction,
) -> bool {
    let PendingAction::StageHost {
        destination,
        device,
        file_type,
        gid: _,
        inode,
        length,
        mode,
        sha256,
        staging,
        transaction_id,
        uid: _,
    } = pending
    else {
        return false;
    };
    *file_type == HostFileType::Regular
        && matches!((device, inode), (None, None) | (Some(_), Some(_)))
        && device.is_none_or(|value| value != 0)
        && inode.is_none_or(|value| value != 0)
        && *length > 0
        && *length <= HOST_FILE_BYTES_MAX
        && valid_host_mode(*mode)
        && valid_transaction_path(destination)
        && destination != "/"
        && valid_staging_leaf(staging)
        && valid_digest(sha256)
        && transaction_id == &transaction.transaction_id
        && resources.iter().all(|resource| match resource {
            HostResource::File(file) => {
                file.path != *destination
                    && device
                        .zip(*inode)
                        .is_none_or(|identity| identity != (file.device, file.inode))
            },
            HostResource::Group(_) | HostResource::User(_) => true,
        })
}

pub(super) fn valid_publish_host(
    pending: &PendingAction,
    resources: &[HostResource],
    transaction: &InstallerTransaction,
) -> bool {
    let PendingAction::PublishHost {
        destination,
        device,
        file_type,
        gid: _,
        inode,
        length,
        mode,
        sha256,
        staging,
        transaction_id,
        uid: _,
    } = pending
    else {
        return false;
    };
    *file_type == HostFileType::Regular
        && *device != 0
        && *inode != 0
        && *length > 0
        && *length <= HOST_FILE_BYTES_MAX
        && valid_host_mode(*mode)
        && valid_transaction_path(destination)
        && destination != "/"
        && valid_staging_leaf(staging)
        && valid_digest(sha256)
        && transaction_id == &transaction.transaction_id
        && resources.iter().all(|resource| match resource {
            HostResource::File(file) => {
                file.path != *destination && (file.device != *device || file.inode != *inode)
            },
            HostResource::Group(_) | HostResource::User(_) => true,
        })
}

fn valid_host_mode(mode: u32) -> bool {
    mode != 0 && mode & !0o777 == 0
}

fn valid_staging_leaf(value: &str) -> bool {
    let path = std::path::Path::new(value);
    !value.is_empty()
        && value.len() <= 255
        && matches!(
            path.components().collect::<Vec<_>>().as_slice(),
            [std::path::Component::Normal(_)]
        )
}

pub(super) fn valid_pending_group(
    resources: &[HostResource],
    gid: u32,
    name: &str,
    transaction_id: &str,
    transaction: &InstallerTransaction,
) -> bool {
    let expected_name = match resources {
        [] => "kapsel",
        [HostResource::Group(_)] => "kapsel-service-callers",
        _ => return false,
    };
    name == expected_name
        && (101..=999).contains(&gid)
        && resources.iter().all(|resource| match resource {
            HostResource::Group(group) => group.gid != gid,
            HostResource::File(_) | HostResource::User(_) => true,
        })
        && transaction_id == transaction.transaction_id
}

#[allow(clippy::too_many_arguments)]
pub(super) fn valid_pending_user(
    resources: &[HostResource],
    uid: u32,
    primary_gid: u32,
    name: &str,
    gecos_transaction_id: &str,
    home: &str,
    shell: &str,
    locked: bool,
    transaction: &InstallerTransaction,
) -> bool {
    let expected = match resources {
        [HostResource::Group(service), HostResource::Group(_)] => {
            ("kapsel", service.gid, "/var/lib/kapsel")
        },
        [HostResource::Group(_), HostResource::Group(callers), HostResource::User(_)] => {
            ("kapsel-service-caller", callers.gid, "/nonexistent")
        },
        _ => return false,
    };
    (101..=999).contains(&uid)
        && resources.iter().all(|resource| match resource {
            HostResource::User(user) => user.uid != uid,
            HostResource::File(_) | HostResource::Group(_) => true,
        })
        && (name, primary_gid, home) == expected
        && gecos_transaction_id == transaction.transaction_id
        && shell == "/usr/sbin/nologin"
        && locked
}

pub(super) fn valid_action_phase(action: Action, phase: TransactionPhase) -> bool {
    match action {
        Action::Install => matches!(
            phase,
            TransactionPhase::Prepared
                | TransactionPhase::Installing
                | TransactionPhase::IdentityBlocked
                | TransactionPhase::Installed
                | TransactionPhase::RollingBack
                | TransactionPhase::RolledBack
        ),
        Action::RefreshCredential => {
            matches!(
                phase,
                TransactionPhase::Refreshing | TransactionPhase::Installed
            )
        },
        Action::Uninstall => matches!(
            phase,
            TransactionPhase::UninstallingLocal
                | TransactionPhase::UninstallingKubernetes
                | TransactionPhase::PartialUninstall
                | TransactionPhase::UninstallingStatic
                | TransactionPhase::Uninstalled
        ),
    }
}

pub(super) fn legal_transaction_successor(
    old: &InstallerTransaction,
    next: &InstallerTransaction,
) -> bool {
    if validate_transaction(old).is_err() || validate_transaction(next).is_err() {
        return false;
    }
    let transition = matches!(
        (old.phase, next.phase),
        (TransactionPhase::Prepared, TransactionPhase::Installing)
            | (
                TransactionPhase::Installing | TransactionPhase::Refreshing,
                TransactionPhase::Installed
            )
            | (TransactionPhase::Installing, TransactionPhase::RollingBack)
            | (TransactionPhase::RollingBack, TransactionPhase::RolledBack)
            | (TransactionPhase::RolledBack, TransactionPhase::Prepared)
            | (
                TransactionPhase::Installed,
                TransactionPhase::Refreshing | TransactionPhase::UninstallingLocal
            )
            | (
                TransactionPhase::UninstallingLocal | TransactionPhase::PartialUninstall,
                TransactionPhase::UninstallingKubernetes
            )
            | (
                TransactionPhase::UninstallingKubernetes,
                TransactionPhase::PartialUninstall | TransactionPhase::UninstallingStatic
            )
            | (
                TransactionPhase::UninstallingStatic,
                TransactionPhase::Uninstalled
            )
    );
    let mut expected = old.clone();
    expected.phase = next.phase;
    expected.action = match (old.phase, next.phase) {
        (TransactionPhase::Installed, TransactionPhase::Refreshing) => Action::RefreshCredential,
        (TransactionPhase::Installed, TransactionPhase::UninstallingLocal) => Action::Uninstall,
        _ => old.action,
    };
    let phase_successor = transition
        && old.pending.is_none()
        && valid_action_phase(next.action, next.phase)
        && next == &expected;

    let mut renewed = old.clone();
    renewed
        .bootstrap_kubeconfig_sha256
        .clone_from(&next.bootstrap_kubeconfig_sha256);
    let digest_successor = old.phase == next.phase
        && old.phase != TransactionPhase::IdentityBlocked
        && old.pending.is_none()
        && old.bootstrap_kubeconfig_sha256 != next.bootstrap_kubeconfig_sha256
        && valid_digest(&next.bootstrap_kubeconfig_sha256)
        && next == &renewed;

    let identity_block_successor = old.action == Action::Install
        && old.phase == TransactionPhase::Installing
        && next.phase == TransactionPhase::IdentityBlocked
        && old.host_resources.len() >= 2
        && !matches!(old.pending, Some(PendingAction::CreateGroup { .. }))
        && next == &expected;

    phase_successor
        || digest_successor
        || identity_block_successor
        || legal_pending_successor(old, next)
}

pub(super) fn legal_pending_successor(
    old: &InstallerTransaction,
    next: &InstallerTransaction,
) -> bool {
    if old.phase != next.phase || old.action != next.action {
        return false;
    }
    if matches!(
        old.pending,
        Some(PendingAction::StageHost { .. } | PendingAction::PublishHost { .. })
    ) {
        return legal_host_file_successor(old, next);
    }
    let mut expected = old.clone();
    match old.pending.as_ref() {
        None if old.phase == TransactionPhase::Installing => {
            expected.pending.clone_from(&next.pending);
            let valid_new_pending = matches!(
                next.pending,
                Some(PendingAction::CreateGroup { .. } | PendingAction::CreateUser { .. })
            ) || matches!(
                next.pending,
                Some(PendingAction::StageHost {
                    device: None,
                    inode: None,
                    ..
                })
            );
            valid_new_pending && next == &expected
        },
        Some(PendingAction::CreateGroup {
            gid,
            name,
            transaction_id: _,
        }) if old.phase == TransactionPhase::Installing => {
            expected.pending = None;
            expected
                .host_resources
                .push(HostResource::Group(GroupResource {
                    gid: *gid,
                    kind: GroupResourceKind::Group,
                    name: name.clone(),
                }));
            next == &expected
        },
        Some(PendingAction::CreateUser {
            gecos_transaction_id,
            home,
            locked,
            name,
            primary_gid,
            shell,
            uid,
        }) if old.phase == TransactionPhase::Installing => {
            expected.pending = None;
            expected
                .host_resources
                .push(HostResource::User(UserResource {
                    gecos_transaction_id: gecos_transaction_id.clone(),
                    home: home.clone(),
                    kind: UserResourceKind::User,
                    locked: *locked,
                    name: name.clone(),
                    primary_gid: *primary_gid,
                    shell: shell.clone(),
                    uid: *uid,
                }));
            next == &expected
        },
        None if old.phase == TransactionPhase::RollingBack => {
            let Some(HostResource::Group(group)) = old.host_resources.last() else {
                return false;
            };
            expected.pending = Some(PendingAction::RemoveGroup {
                group: group.clone(),
            });
            next == &expected
        },
        Some(PendingAction::RemoveGroup { group })
            if old.phase == TransactionPhase::RollingBack
                && old.host_resources.last() == Some(&HostResource::Group(group.clone())) =>
        {
            expected.pending = None;
            expected.host_resources.pop();
            next == &expected
        },
        _ => false,
    }
}

fn legal_host_file_successor(old: &InstallerTransaction, next: &InstallerTransaction) -> bool {
    if old.phase != TransactionPhase::Installing {
        return false;
    }
    let mut expected = old.clone();
    match old.pending.as_ref() {
        Some(PendingAction::StageHost {
            device: None,
            inode: None,
            ..
        }) => {
            let Some(PendingAction::StageHost {
                device: Some(device),
                inode: Some(inode),
                ..
            }) = next.pending.as_ref()
            else {
                return false;
            };
            let Some(PendingAction::StageHost {
                device: expected_device,
                inode: expected_inode,
                ..
            }) = expected.pending.as_mut()
            else {
                return false;
            };
            *expected_device = Some(*device);
            *expected_inode = Some(*inode);
            next == &expected
        },
        Some(PendingAction::StageHost {
            destination,
            device: Some(device),
            file_type,
            gid,
            inode: Some(inode),
            length,
            mode,
            sha256,
            staging,
            transaction_id,
            uid,
        }) => {
            expected.pending = Some(PendingAction::PublishHost {
                destination: destination.clone(),
                device: *device,
                file_type: *file_type,
                gid: *gid,
                inode: *inode,
                length: *length,
                mode: *mode,
                sha256: sha256.clone(),
                staging: staging.clone(),
                transaction_id: transaction_id.clone(),
                uid: *uid,
            });
            next == &expected
        },
        Some(PendingAction::PublishHost {
            destination,
            device,
            file_type,
            gid,
            inode,
            length,
            mode,
            sha256,
            staging: _,
            transaction_id: _,
            uid,
        }) => {
            expected.pending = None;
            expected
                .host_resources
                .push(HostResource::File(FileResource {
                    device: *device,
                    file_type: *file_type,
                    gid: *gid,
                    inode: *inode,
                    kind: FileResourceKind::File,
                    length: *length,
                    mode: *mode,
                    path: destination.clone(),
                    sha256: sha256.clone(),
                    uid: *uid,
                }));
            next == &expected
        },
        _ => false,
    }
}

pub(super) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn valid_transaction_path(value: &str) -> bool {
    let path = std::path::Path::new(value);
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_transaction_has_exact_canonical_schema_one_bytes() {
        let h1 = "11".repeat(32);
        let h2 = "22".repeat(32);
        let h3 = "33".repeat(32);
        let h4 = "44".repeat(32);
        let h5 = "55".repeat(32);
        let h6 = "66".repeat(32);
        let h7 = "77".repeat(32);
        let h8 = "88".repeat(32);
        let expected = [
            r#"{"action":"install","bootstrap_kubeconfig_initial_sha256":""#,
            &h1,
            r#"","bootstrap_kubeconfig_sha256":""#,
            &h1,
            r#"","cluster":{"ca_sha256":""#,
            &h2,
            r#"","server":"https://127.0.0.1:6443"},"credential_expiration":null,"#,
            r#""host_resources":[],"input_directory":{"device":1,"inode":2,"mode":448,"#,
            r#""path":"/secure/kapsel","uid":0},"installer_sha256":""#,
            &h3,
            r#"","kube_context":"nonprod","kubernetes_resources":[],"operator_inputs":{"#,
            r#""authorization.pub":""#,
            &h4,
            r#"","grant.bin":""#,
            &h5,
            r#"","receipt.seed":""#,
            &h6,
            r#"","receipt.trust":""#,
            &h7,
            r#""},"pending":null,"phase":"prepared","schema":1,"transaction_id":""#,
            &h8,
            r#""}"#,
        ]
        .concat();
        let encoded = encode_transaction(&test_initial_transaction()).expect("fixture must encode");
        assert_eq!(encoded, expected.as_bytes());
        assert_eq!(
            decode_transaction(&encoded).expect("canonical bytes must decode"),
            test_initial_transaction()
        );
        for secret in [
            "fixture-token",
            "private-key",
            "receipt-seed-bytes",
            "grant-bytes",
        ] {
            assert!(!expected.contains(secret));
        }
    }

    #[test]
    fn initial_transaction_rejects_noncanonical_hostile_and_nonprepared_records() {
        let canonical = String::from_utf8(
            encode_transaction(&test_initial_transaction()).expect("fixture must encode"),
        )
        .expect("fixture must be UTF-8");
        let reordered = format!(
            "{{\"schema\":1,{}",
            canonical[1..].replacen(",\"schema\":1", "", 1)
        );
        let cases = [
            format!(" {canonical}"),
            format!("{canonical}\n"),
            canonical.replacen("\"action\":\"install\"", "\"action\":\"uninstall\"", 1),
            canonical.replacen("\"phase\":\"prepared\"", "\"phase\":\"refreshing\"", 1),
            canonical.replacen("\"action\":", "\"unknown\":null,\"action\":", 1),
            canonical.replacen(
                "\"action\":\"install\"",
                "\"action\":\"install\",\"action\":\"install\"",
                1,
            ),
            canonical.replacen(&"33".repeat(32), &"AA".repeat(32), 1),
            canonical.replacen("https://", r"https:\/\/", 1),
            canonical.replacen("\"host_resources\":[]", "\"host_resources\":[{}]", 1),
            reordered,
        ];
        for (index, bytes) in cases.into_iter().enumerate() {
            assert!(
                matches!(
                    decode_transaction(bytes.as_bytes()),
                    Err(InstallerError::TransactionFailure)
                ),
                "hostile transaction case {index} was accepted"
            );
        }
        assert!(matches!(
            decode_transaction(&vec![b' '; TRANSACTION_BYTES_MAX + 1]),
            Err(InstallerError::TransactionFailure)
        ));
        for (action, expected) in [
            (Action::Install, "\"install\""),
            (Action::RefreshCredential, "\"refresh-credential\""),
            (Action::Uninstall, "\"uninstall\""),
        ] {
            assert_eq!(
                serde_json::to_string(&action).expect("action must encode"),
                expected
            );
        }
    }

    #[test]
    fn phase_successors_are_exact_and_change_nothing_else() {
        let edges = [
            (
                Action::Install,
                TransactionPhase::Prepared,
                Action::Install,
                TransactionPhase::Installing,
            ),
            (
                Action::Install,
                TransactionPhase::Installing,
                Action::Install,
                TransactionPhase::Installed,
            ),
            (
                Action::Install,
                TransactionPhase::Installing,
                Action::Install,
                TransactionPhase::RollingBack,
            ),
            (
                Action::Install,
                TransactionPhase::RollingBack,
                Action::Install,
                TransactionPhase::RolledBack,
            ),
            (
                Action::Install,
                TransactionPhase::RolledBack,
                Action::Install,
                TransactionPhase::Prepared,
            ),
            (
                Action::Install,
                TransactionPhase::Installed,
                Action::RefreshCredential,
                TransactionPhase::Refreshing,
            ),
            (
                Action::RefreshCredential,
                TransactionPhase::Refreshing,
                Action::RefreshCredential,
                TransactionPhase::Installed,
            ),
            (
                Action::Install,
                TransactionPhase::Installed,
                Action::Uninstall,
                TransactionPhase::UninstallingLocal,
            ),
            (
                Action::Uninstall,
                TransactionPhase::UninstallingLocal,
                Action::Uninstall,
                TransactionPhase::UninstallingKubernetes,
            ),
            (
                Action::Uninstall,
                TransactionPhase::UninstallingKubernetes,
                Action::Uninstall,
                TransactionPhase::PartialUninstall,
            ),
            (
                Action::Uninstall,
                TransactionPhase::PartialUninstall,
                Action::Uninstall,
                TransactionPhase::UninstallingKubernetes,
            ),
            (
                Action::Uninstall,
                TransactionPhase::UninstallingKubernetes,
                Action::Uninstall,
                TransactionPhase::UninstallingStatic,
            ),
            (
                Action::Uninstall,
                TransactionPhase::UninstallingStatic,
                Action::Uninstall,
                TransactionPhase::Uninstalled,
            ),
        ];
        for (old_action, old_phase, next_action, next_phase) in edges {
            let mut old = test_initial_transaction();
            old.action = old_action;
            old.phase = old_phase;
            let mut next = old.clone();
            next.action = next_action;
            next.phase = next_phase;
            assert!(legal_transaction_successor(&old, &next));
            next.cluster.ca_sha256 = "99".repeat(32);
            assert!(!legal_transaction_successor(&old, &next));
        }
        let old = test_initial_transaction();
        let mut skipped = old.clone();
        skipped.phase = TransactionPhase::Installed;
        assert!(!legal_transaction_successor(&old, &skipped));
    }

    #[test]
    fn first_group_pending_and_ownership_successors_are_exact() {
        let mut installing = test_initial_transaction();
        installing.phase = TransactionPhase::Installing;

        let pending = PendingAction::CreateGroup {
            name: String::from("kapsel"),
            gid: 999,
            transaction_id: installing.transaction_id.clone(),
        };
        let mut creating = installing.clone();
        creating.pending = Some(pending.clone());
        assert!(legal_transaction_successor(&installing, &creating));
        assert_eq!(
            serde_json::to_string(&pending).unwrap(),
            format!(
                r#"{{"action":"create_group","gid":999,"name":"kapsel","transaction_id":"{}"}}"#,
                installing.transaction_id
            )
        );

        let group = GroupResource {
            gid: 999,
            kind: GroupResourceKind::Group,
            name: String::from("kapsel"),
        };
        let mut created = creating.clone();
        created.pending = None;
        created
            .host_resources
            .push(HostResource::Group(group.clone()));
        assert!(legal_transaction_successor(&creating, &created));

        let mut rolling_back = created.clone();
        rolling_back.phase = TransactionPhase::RollingBack;
        assert!(legal_transaction_successor(&created, &rolling_back));
        let mut removing = rolling_back.clone();
        removing.pending = Some(PendingAction::RemoveGroup { group });
        assert!(legal_transaction_successor(&rolling_back, &removing));
        let mut removed = removing.clone();
        removed.pending = None;
        removed.host_resources.clear();
        assert!(legal_transaction_successor(&removing, &removed));

        let mut missing_evidence = creating.clone();
        missing_evidence.pending = None;
        assert!(!legal_transaction_successor(&creating, &missing_evidence));

        let mut wrong_evidence = missing_evidence;
        wrong_evidence
            .host_resources
            .push(HostResource::Group(GroupResource {
                gid: 998,
                kind: GroupResourceKind::Group,
                name: String::from("kapsel"),
            }));
        assert!(!legal_transaction_successor(&creating, &wrong_evidence));

        let mut hostile = creating;
        hostile.pending = Some(PendingAction::CreateGroup {
            name: String::from("other"),
            gid: 999,
            transaction_id: hostile.transaction_id.clone(),
        });
        assert!(!legal_transaction_successor(&installing, &hostile));
    }

    #[test]
    fn second_group_pending_ownership_and_reverse_removal_are_exact() {
        let mut first_created = test_initial_transaction();
        first_created.phase = TransactionPhase::Installing;
        first_created
            .host_resources
            .push(HostResource::Group(GroupResource {
                gid: 999,
                kind: GroupResourceKind::Group,
                name: String::from("kapsel"),
            }));
        let mut second_pending = first_created.clone();
        second_pending.pending = Some(PendingAction::CreateGroup {
            gid: 998,
            name: String::from("kapsel-service-callers"),
            transaction_id: first_created.transaction_id.clone(),
        });
        assert!(legal_transaction_successor(&first_created, &second_pending));

        let second = GroupResource {
            gid: 998,
            kind: GroupResourceKind::Group,
            name: String::from("kapsel-service-callers"),
        };
        let mut second_created = second_pending.clone();
        second_created.pending = None;
        second_created
            .host_resources
            .push(HostResource::Group(second.clone()));
        assert!(legal_transaction_successor(
            &second_pending,
            &second_created
        ));

        let mut rolling_back = second_created.clone();
        rolling_back.phase = TransactionPhase::RollingBack;
        assert!(legal_transaction_successor(&second_created, &rolling_back));
        let mut removing_second = rolling_back.clone();
        removing_second.pending = Some(PendingAction::RemoveGroup { group: second });
        assert!(legal_transaction_successor(&rolling_back, &removing_second));
        let mut second_removed = removing_second.clone();
        second_removed.pending = None;
        second_removed.host_resources.pop();
        assert!(legal_transaction_successor(
            &removing_second,
            &second_removed
        ));

        let mut duplicate_gid = second_pending;
        if let Some(PendingAction::CreateGroup { gid, .. }) = duplicate_gid.pending.as_mut() {
            *gid = 999;
        }
        assert!(validate_transaction(&duplicate_gid).is_err());
        let mut wrong_removal = rolling_back;
        let HostResource::Group(first_group) = &first_created.host_resources[0] else {
            return;
        };
        wrong_removal.pending = Some(PendingAction::RemoveGroup {
            group: first_group.clone(),
        });
        assert!(validate_transaction(&wrong_removal).is_err());
    }

    #[test]
    fn user_pending_and_ownership_successors_are_exact() {
        let mut installing = test_initial_transaction();
        installing.phase = TransactionPhase::Installing;
        installing
            .host_resources
            .push(HostResource::Group(GroupResource {
                gid: 999,
                kind: GroupResourceKind::Group,
                name: String::from("kapsel"),
            }));
        installing
            .host_resources
            .push(HostResource::Group(GroupResource {
                gid: 998,
                kind: GroupResourceKind::Group,
                name: String::from("kapsel-service-callers"),
            }));
        let pending = PendingAction::CreateUser {
            gecos_transaction_id: installing.transaction_id.clone(),
            home: String::from("/var/lib/kapsel"),
            locked: true,
            name: String::from("kapsel"),
            primary_gid: 999,
            shell: String::from("/usr/sbin/nologin"),
            uid: 997,
        };
        let mut creating = installing.clone();
        creating.pending = Some(pending.clone());
        assert!(legal_transaction_successor(&installing, &creating));
        let encoded_pending = [
            r#"{"action":"create_user","gecos_transaction_id":""#,
            &installing.transaction_id,
            r#"","home":"/var/lib/kapsel","locked":true,"name":"kapsel","#,
            r#""primary_gid":999,"shell":"/usr/sbin/nologin","uid":997}"#,
        ]
        .concat();
        assert_eq!(serde_json::to_string(&pending).unwrap(), encoded_pending);
        let mut created = creating.clone();
        created.pending = None;
        created
            .host_resources
            .push(HostResource::User(UserResource {
                gecos_transaction_id: installing.transaction_id.clone(),
                home: String::from("/var/lib/kapsel"),
                kind: UserResourceKind::User,
                locked: true,
                name: String::from("kapsel"),
                primary_gid: 999,
                shell: String::from("/usr/sbin/nologin"),
                uid: 997,
            }));
        assert!(legal_transaction_successor(&creating, &created));

        let mut caller_pending = created.clone();
        caller_pending.pending = Some(PendingAction::CreateUser {
            gecos_transaction_id: installing.transaction_id.clone(),
            home: String::from("/nonexistent"),
            locked: true,
            name: String::from("kapsel-service-caller"),
            primary_gid: 998,
            shell: String::from("/usr/sbin/nologin"),
            uid: 996,
        });
        assert!(legal_transaction_successor(&created, &caller_pending));
        let mut caller_created = caller_pending.clone();
        caller_created.pending = None;
        caller_created
            .host_resources
            .push(HostResource::User(UserResource {
                gecos_transaction_id: installing.transaction_id.clone(),
                home: String::from("/nonexistent"),
                kind: UserResourceKind::User,
                locked: true,
                name: String::from("kapsel-service-caller"),
                primary_gid: 998,
                shell: String::from("/usr/sbin/nologin"),
                uid: 996,
            }));
        assert!(legal_transaction_successor(
            &caller_pending,
            &caller_created
        ));

        let mut wrong_uid = creating;
        if let Some(PendingAction::CreateUser { uid, .. }) = wrong_uid.pending.as_mut() {
            *uid = 1_000;
        }
        assert!(validate_transaction(&wrong_uid).is_err());
        let mut duplicate_uid = caller_pending;
        if let Some(PendingAction::CreateUser { uid, .. }) = duplicate_uid.pending.as_mut() {
            *uid = 997;
        }
        assert!(validate_transaction(&duplicate_uid).is_err());
        let mut rollback = created;
        rollback.phase = TransactionPhase::RollingBack;
        assert!(validate_transaction(&rollback).is_err());
    }

    #[test]
    fn identity_block_is_durable_terminal_state_at_user_boundaries() {
        let mut installing = test_initial_transaction();
        installing.phase = TransactionPhase::Installing;
        installing
            .host_resources
            .push(HostResource::Group(GroupResource {
                gid: 999,
                kind: GroupResourceKind::Group,
                name: String::from("kapsel"),
            }));
        installing
            .host_resources
            .push(HostResource::Group(GroupResource {
                gid: 998,
                kind: GroupResourceKind::Group,
                name: String::from("kapsel-service-callers"),
            }));
        let mut creating = installing.clone();
        creating.pending = Some(PendingAction::CreateUser {
            gecos_transaction_id: installing.transaction_id.clone(),
            home: String::from("/var/lib/kapsel"),
            locked: true,
            name: String::from("kapsel"),
            primary_gid: 999,
            shell: String::from("/usr/sbin/nologin"),
            uid: 997,
        });
        for source in [&installing, &creating] {
            let mut blocked = source.clone();
            blocked.phase = TransactionPhase::IdentityBlocked;
            assert!(legal_transaction_successor(source, &blocked));
            let mut resumed = blocked.clone();
            resumed.phase = TransactionPhase::Installing;
            assert!(!legal_transaction_successor(&blocked, &resumed));
            let mut rolling_back = blocked.clone();
            rolling_back.phase = TransactionPhase::RollingBack;
            assert!(!legal_transaction_successor(&blocked, &rolling_back));
            let mut renewed = blocked.clone();
            renewed.bootstrap_kubeconfig_sha256 = "99".repeat(32);
            assert!(!legal_transaction_successor(&blocked, &renewed));
        }
    }

    #[test]
    fn bootstrap_digest_successor_is_same_phase_and_initial_digest_is_immutable() {
        let old = test_initial_transaction();
        let mut renewed = old.clone();
        renewed.bootstrap_kubeconfig_sha256 = "99".repeat(32);
        assert!(legal_transaction_successor(&old, &renewed));
        renewed.bootstrap_kubeconfig_initial_sha256 = "99".repeat(32);
        assert!(!legal_transaction_successor(&old, &renewed));

        let mut installing = old.clone();
        installing.phase = TransactionPhase::Installing;
        installing.bootstrap_kubeconfig_sha256 = "99".repeat(32);
        assert!(!legal_transaction_successor(&old, &installing));
    }

    fn complete_identity_transaction() -> InstallerTransaction {
        let mut transaction = test_initial_transaction();
        transaction.phase = TransactionPhase::Installing;
        transaction.host_resources = vec![
            HostResource::Group(GroupResource {
                gid: 999,
                kind: GroupResourceKind::Group,
                name: String::from("kapsel"),
            }),
            HostResource::Group(GroupResource {
                gid: 998,
                kind: GroupResourceKind::Group,
                name: String::from("kapsel-service-callers"),
            }),
            HostResource::User(UserResource {
                gecos_transaction_id: transaction.transaction_id.clone(),
                home: String::from("/var/lib/kapsel"),
                kind: UserResourceKind::User,
                locked: true,
                name: String::from("kapsel"),
                primary_gid: 999,
                shell: String::from("/usr/sbin/nologin"),
                uid: 997,
            }),
            HostResource::User(UserResource {
                gecos_transaction_id: transaction.transaction_id.clone(),
                home: String::from("/nonexistent"),
                kind: UserResourceKind::User,
                locked: true,
                name: String::from("kapsel-service-caller"),
                primary_gid: 998,
                shell: String::from("/usr/sbin/nologin"),
                uid: 996,
            }),
        ];
        transaction
    }

    fn host_stage(transaction: &InstallerTransaction) -> PendingAction {
        PendingAction::StageHost {
            destination: String::from("/usr/bin/kapsel"),
            device: None,
            file_type: HostFileType::Regular,
            gid: 0,
            inode: None,
            length: 120,
            mode: 0o755,
            sha256: "99".repeat(32),
            staging: String::from(".kapsel-stage-fixture"),
            transaction_id: transaction.transaction_id.clone(),
            uid: 0,
        }
    }

    fn host_publish(transaction: &InstallerTransaction) -> PendingAction {
        PendingAction::PublishHost {
            destination: String::from("/usr/bin/kapsel"),
            device: 7,
            file_type: HostFileType::Regular,
            gid: 0,
            inode: 11,
            length: 120,
            mode: 0o755,
            sha256: "99".repeat(32),
            staging: String::from(".kapsel-stage-fixture"),
            transaction_id: transaction.transaction_id.clone(),
            uid: 0,
        }
    }

    fn assert_publish_pending_rejected(
        bound: &InstallerTransaction,
        mutate: impl FnOnce(&mut PendingAction),
    ) {
        let mut candidate = bound.clone();
        candidate.pending = Some(host_publish(bound));
        mutate(
            candidate
                .pending
                .as_mut()
                .expect("publish pending must exist"),
        );
        assert!(!legal_transaction_successor(bound, &candidate));
    }

    fn assert_file_ownership_rejected(
        publishing: &InstallerTransaction,
        mutate: impl FnOnce(&mut FileResource),
    ) {
        let PendingAction::PublishHost {
            destination,
            device,
            file_type,
            gid,
            inode,
            length,
            mode,
            sha256,
            uid,
            ..
        } = publishing
            .pending
            .as_ref()
            .expect("publish pending must exist")
        else {
            return;
        };
        let mut candidate = publishing.clone();
        candidate.pending = None;
        let mut file = FileResource {
            device: *device,
            file_type: *file_type,
            gid: *gid,
            inode: *inode,
            kind: FileResourceKind::File,
            length: *length,
            mode: *mode,
            path: destination.clone(),
            sha256: sha256.clone(),
            uid: *uid,
        };
        mutate(&mut file);
        candidate.host_resources.push(HostResource::File(file));
        assert!(!legal_transaction_successor(publishing, &candidate));
    }

    #[test]
    fn host_file_stage_bind_publish_and_ownership_successors_are_exact() {
        let installing = complete_identity_transaction();
        let mut staging = installing.clone();
        staging.pending = Some(host_stage(&installing));
        assert!(legal_transaction_successor(&installing, &staging));

        let mut bound = staging.clone();
        let PendingAction::StageHost { device, inode, .. } = bound.pending.as_mut().unwrap() else {
            return;
        };
        *device = Some(7);
        *inode = Some(11);
        assert!(legal_transaction_successor(&staging, &bound));

        let mut publishing = bound.clone();
        publishing.pending = Some(host_publish(&bound));
        assert!(legal_transaction_successor(&bound, &publishing));

        let file = FileResource {
            device: 7,
            file_type: HostFileType::Regular,
            gid: 0,
            inode: 11,
            kind: FileResourceKind::File,
            length: 120,
            mode: 0o755,
            path: String::from("/usr/bin/kapsel"),
            sha256: "99".repeat(32),
            uid: 0,
        };
        let mut published = publishing.clone();
        published.pending = None;
        published.host_resources.push(HostResource::File(file));
        assert!(legal_transaction_successor(&publishing, &published));
        let encoded = encode_transaction(&published).expect("host file record must encode");
        assert_eq!(
            decode_transaction(&encoded).expect("host file record must decode"),
            published
        );

        let mut skipped = staging.clone();
        skipped.pending = publishing.pending;
        assert!(!legal_transaction_successor(&staging, &skipped));
        let mut unrelated = bound.clone();
        unrelated.cluster.ca_sha256 = "aa".repeat(32);
        assert!(!legal_transaction_successor(&staging, &unrelated));
    }

    #[test]
    fn host_file_successors_reject_every_changed_frozen_fact() {
        let mut bound = complete_identity_transaction();
        bound.pending = Some(PendingAction::StageHost {
            destination: String::from("/usr/bin/kapsel"),
            device: Some(7),
            file_type: HostFileType::Regular,
            gid: 0,
            inode: Some(11),
            length: 120,
            mode: 0o755,
            sha256: "99".repeat(32),
            staging: String::from(".kapsel-stage-fixture"),
            transaction_id: bound.transaction_id.clone(),
            uid: 0,
        });
        let mut publishing = bound.clone();
        publishing.pending = Some(host_publish(&bound));

        assert_publish_pending_rejected(&bound, |pending| {
            let PendingAction::PublishHost { destination, .. } = pending else {
                return;
            };
            *destination = String::from("/usr/bin/other");
        });
        assert_publish_pending_rejected(&bound, |pending| {
            let PendingAction::PublishHost { device, .. } = pending else {
                return;
            };
            *device = 8;
        });
        assert_publish_pending_rejected(&bound, |pending| {
            let PendingAction::PublishHost { gid, .. } = pending else {
                return;
            };
            *gid = 1;
        });
        assert_publish_pending_rejected(&bound, |pending| {
            let PendingAction::PublishHost { inode, .. } = pending else {
                return;
            };
            *inode = 12;
        });
        assert_publish_pending_rejected(&bound, |pending| {
            let PendingAction::PublishHost { length, .. } = pending else {
                return;
            };
            *length = 121;
        });
        assert_publish_pending_rejected(&bound, |pending| {
            let PendingAction::PublishHost { mode, .. } = pending else {
                return;
            };
            *mode = 0o644;
        });
        assert_publish_pending_rejected(&bound, |pending| {
            let PendingAction::PublishHost { sha256, .. } = pending else {
                return;
            };
            *sha256 = "aa".repeat(32);
        });
        assert_publish_pending_rejected(&bound, |pending| {
            let PendingAction::PublishHost { staging, .. } = pending else {
                return;
            };
            *staging = String::from(".other-stage");
        });
        assert_publish_pending_rejected(&bound, |pending| {
            let PendingAction::PublishHost { transaction_id, .. } = pending else {
                return;
            };
            *transaction_id = "aa".repeat(32);
        });
        assert_publish_pending_rejected(&bound, |pending| {
            let PendingAction::PublishHost { uid, .. } = pending else {
                return;
            };
            *uid = 1;
        });

        assert_file_ownership_rejected(&publishing, |file| {
            file.path = String::from("/usr/bin/other");
        });
        assert_file_ownership_rejected(&publishing, |file| file.device = 8);
        assert_file_ownership_rejected(&publishing, |file| file.gid = 1);
        assert_file_ownership_rejected(&publishing, |file| file.inode = 12);
        assert_file_ownership_rejected(&publishing, |file| file.length = 121);
        assert_file_ownership_rejected(&publishing, |file| file.mode = 0o644);
        assert_file_ownership_rejected(&publishing, |file| file.sha256 = "aa".repeat(32));
        assert_file_ownership_rejected(&publishing, |file| file.uid = 1);
    }

    #[test]
    fn host_file_state_rejects_hostile_shapes_and_duplicate_destinations() {
        let installing = complete_identity_transaction();
        let mut stage = installing.clone();
        stage.pending = Some(host_stage(&installing));
        let canonical = encode_transaction(&stage).expect("stage must encode");
        let canonical = String::from_utf8(canonical).expect("stage must be UTF-8");
        for (index, hostile) in [
            canonical.replacen("\"device\":null", "\"device\":1", 1),
            canonical.replacen("\"mode\":493", "\"mode\":4096", 1),
            canonical.replacen("\"length\":120", "\"length\":0", 1),
            canonical.replacen("/usr/bin/kapsel", "relative", 1),
            canonical.replacen(".kapsel-stage-fixture", "../stage", 1),
            canonical.replacen(&"99".repeat(32), "bad", 1),
            canonical.replacen("\"uid\":0", "\"unknown\":0,\"uid\":0", 1),
        ]
        .into_iter()
        .enumerate()
        {
            assert!(
                decode_transaction(hostile.as_bytes()).is_err(),
                "hostile host-file case {index} was accepted"
            );
        }

        let mut publishing = installing.clone();
        publishing.pending = Some(host_publish(&installing));
        let file = FileResource {
            device: 7,
            file_type: HostFileType::Regular,
            gid: 0,
            inode: 11,
            kind: FileResourceKind::File,
            length: 120,
            mode: 0o755,
            path: String::from("/usr/bin/kapsel"),
            sha256: "99".repeat(32),
            uid: 0,
        };
        publishing
            .host_resources
            .push(HostResource::File(file.clone()));
        assert!(validate_transaction(&publishing).is_err());

        let mut duplicate = installing;
        duplicate
            .host_resources
            .push(HostResource::File(file.clone()));
        let mut second = file.clone();
        second.device = 8;
        second.inode = 12;
        duplicate.host_resources.push(HostResource::File(second));
        assert!(validate_transaction(&duplicate).is_err());

        let mut duplicate_inode = complete_identity_transaction();
        duplicate_inode
            .host_resources
            .push(HostResource::File(file.clone()));
        let mut second = file.clone();
        second.path = String::from("/usr/bin/other");
        duplicate_inode
            .host_resources
            .push(HostResource::File(second));
        assert!(validate_transaction(&duplicate_inode).is_err());

        let mut reused_stage = complete_identity_transaction();
        reused_stage.host_resources.push(HostResource::File(file));
        let mut pending = host_stage(&reused_stage);
        let PendingAction::StageHost {
            destination,
            device,
            inode,
            ..
        } = &mut pending
        else {
            return;
        };
        *destination = String::from("/usr/bin/other");
        *device = Some(7);
        *inode = Some(11);
        reused_stage.pending = Some(pending);
        assert!(validate_transaction(&reused_stage).is_err());
    }

    #[test]
    fn install_phase_reopening_is_explicit_and_other_phases_fail_closed() {
        assert_eq!(
            classify_install_phase(TransactionPhase::IdentityBlocked).unwrap(),
            InstallPhase::Blocked
        );
        assert_eq!(
            classify_install_phase(TransactionPhase::Prepared).unwrap(),
            InstallPhase::Prepared
        );
        assert_eq!(
            classify_install_phase(TransactionPhase::Installing).unwrap(),
            InstallPhase::Installing
        );
        assert_eq!(
            classify_install_phase(TransactionPhase::RollingBack).unwrap(),
            InstallPhase::RollingBack
        );
        assert_eq!(
            classify_install_phase(TransactionPhase::RolledBack).unwrap(),
            InstallPhase::RolledBack
        );
        assert!(classify_install_phase(TransactionPhase::Installed).is_err());
    }
}
