//! Portable installer identity selection and observation rules.

use std::collections::BTreeSet;

use super::*;

pub(super) struct BoundedCommandOutput {
    pub(super) status: i32,
    pub(super) stdout: Vec<u8>,
}

pub(super) struct UserSpec {
    pub(super) name: &'static str,
    pub(super) group_name: &'static str,
    pub(super) home: &'static str,
}

pub(super) const SERVICE_USER: UserSpec = UserSpec {
    name: "kapsel",
    group_name: "kapsel",
    home: "/var/lib/kapsel",
};
pub(super) const CALLER_USER: UserSpec = UserSpec {
    name: "kapsel-service-caller",
    group_name: "kapsel-service-callers",
    home: "/nonexistent",
};

pub(super) fn owned_group_gid(
    transaction: &InstallerTransaction,
    name: &str,
) -> Result<u32, InstallerError> {
    transaction
        .host_resources
        .iter()
        .find_map(|resource| match resource {
            HostResource::Group(group) if group.name == name => Some(group.gid),
            _ => None,
        })
        .ok_or(InstallerError::HostMutationFailure)
}

pub(super) fn pending_user(
    spec: &UserSpec,
    uid: u32,
    primary_gid: u32,
    transaction_id: &str,
) -> PendingAction {
    PendingAction::CreateUser {
        gecos_transaction_id: transaction_id.to_owned(),
        home: spec.home.to_owned(),
        locked: true,
        name: spec.name.to_owned(),
        primary_gid,
        shell: String::from("/usr/sbin/nologin"),
        uid,
    }
}

pub(super) fn user_from_pending(
    transaction: &InstallerTransaction,
    spec: &UserSpec,
) -> Result<UserResource, InstallerError> {
    match transaction.pending.as_ref() {
        Some(
            pending @ PendingAction::CreateUser {
                gecos_transaction_id,
                name,
                ..
            },
        ) if name == spec.name && gecos_transaction_id == &transaction.transaction_id => {
            user_resource_from_pending(pending)
        },
        _ => Err(InstallerError::HostMutationFailure),
    }
}

pub(super) fn user_resource_from_pending(
    pending: &PendingAction,
) -> Result<UserResource, InstallerError> {
    match pending {
        PendingAction::CreateUser {
            gecos_transaction_id,
            home,
            locked,
            name,
            primary_gid,
            shell,
            uid,
        } => Ok(UserResource {
            gecos_transaction_id: gecos_transaction_id.clone(),
            home: home.clone(),
            kind: UserResourceKind::User,
            locked: *locked,
            name: name.clone(),
            primary_gid: *primary_gid,
            shell: shell.clone(),
            uid: *uid,
        }),
        _ => Err(InstallerError::HostMutationFailure),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UserObservation {
    Absent,
    Exact,
    Conflict,
    Ambiguous,
}

pub(super) fn select_user_uid(passwd: &[u8]) -> Result<u32, InstallerError> {
    let used = parse_identity_gids(passwd, 2, 7)?;
    (101..=999)
        .rev()
        .find(|uid| !used.contains(uid))
        .ok_or(InstallerError::HostPreflightFailure)
}

pub(super) fn classify_user_observation(
    by_name: &BoundedCommandOutput,
    by_uid: &BoundedCommandOutput,
    shadow: &BoundedCommandOutput,
    user: &UserResource,
) -> UserObservation {
    let expected_passwd = format!(
        "{}:x:{}:{}:{}:{}:{}\n",
        user.name, user.uid, user.primary_gid, user.gecos_transaction_id, user.home, user.shell
    );
    let name = classify_passwd_query(by_name, expected_passwd.as_bytes());
    let uid = classify_passwd_query(by_uid, expected_passwd.as_bytes());
    if name == RecordObservation::Conflict || uid == RecordObservation::Conflict {
        return UserObservation::Conflict;
    }

    let shadow = classify_shadow_query(shadow, user);
    match (name, uid, shadow) {
        (RecordObservation::Absent, RecordObservation::Absent, RecordObservation::Absent) => {
            UserObservation::Absent
        },
        (RecordObservation::Exact, RecordObservation::Exact, RecordObservation::Exact) => {
            UserObservation::Exact
        },
        _ => UserObservation::Ambiguous,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordObservation {
    Absent,
    Exact,
    Conflict,
    Ambiguous,
}

fn classify_passwd_query(query: &BoundedCommandOutput, expected: &[u8]) -> RecordObservation {
    if query.status == 2 && query.stdout.is_empty() {
        return RecordObservation::Absent;
    }
    if query.status != 0 {
        return RecordObservation::Ambiguous;
    }
    if query.stdout == expected {
        return RecordObservation::Exact;
    }
    if valid_single_passwd_record(&query.stdout) {
        RecordObservation::Conflict
    } else {
        RecordObservation::Ambiguous
    }
}

fn valid_single_passwd_record(bytes: &[u8]) -> bool {
    let Ok(record) = std::str::from_utf8(bytes) else {
        return false;
    };
    let Some(record) = record.strip_suffix('\n') else {
        return false;
    };
    let fields = record.split(':').collect::<Vec<_>>();
    fields.len() == 7
        && !fields[0].is_empty()
        && canonical_u32(fields[2])
        && canonical_u32(fields[3])
}

fn classify_shadow_query(query: &BoundedCommandOutput, user: &UserResource) -> RecordObservation {
    if query.status == 2 && query.stdout.is_empty() {
        return RecordObservation::Absent;
    }
    if query.status != 0 {
        return RecordObservation::Ambiguous;
    }
    let Ok(record) = std::str::from_utf8(&query.stdout) else {
        return RecordObservation::Ambiguous;
    };
    let Some(record) = record.strip_suffix('\n') else {
        return RecordObservation::Ambiguous;
    };
    let fields = record.split(':').collect::<Vec<_>>();
    if fields.len() == 9
        && fields[0] == user.name
        && fields[1] == "!"
        && !fields[2].is_empty()
        && fields[2].bytes().all(|byte| byte.is_ascii_digit())
        && fields[3..].iter().all(|field| field.is_empty())
    {
        RecordObservation::Exact
    } else {
        RecordObservation::Ambiguous
    }
}

fn canonical_u32(encoded: &str) -> bool {
    encoded
        .parse::<u32>()
        .is_ok_and(|value| encoded == value.to_string())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GroupObservation {
    Absent,
    Exact,
}

pub(super) fn select_group_gid(groups: &[u8], passwd: &[u8]) -> Result<u32, InstallerError> {
    let mut used = parse_identity_gids(groups, 2, 4)?;
    used.extend(parse_identity_gids(passwd, 3, 7)?);
    (101..=999)
        .rev()
        .find(|gid| !used.contains(gid))
        .ok_or(InstallerError::HostPreflightFailure)
}

pub(super) fn parse_identity_gids(
    bytes: &[u8],
    gid_field: usize,
    field_count: usize,
) -> Result<BTreeSet<u32>, InstallerError> {
    if bytes.is_empty() || !bytes.ends_with(b"\n") {
        return Err(InstallerError::HostPreflightFailure);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| InstallerError::HostPreflightFailure)?;
    let mut gids = BTreeSet::new();
    for line in text.lines() {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() != field_count || fields[0].is_empty() {
            return Err(InstallerError::HostPreflightFailure);
        }
        let encoded = fields
            .get(gid_field)
            .ok_or(InstallerError::HostPreflightFailure)?;
        let gid = encoded
            .parse::<u32>()
            .map_err(|_| InstallerError::HostPreflightFailure)?;
        if encoded != &gid.to_string() {
            return Err(InstallerError::HostPreflightFailure);
        }
        gids.insert(gid);
    }
    Ok(gids)
}

pub(super) fn classify_group_observation(
    name_status: i32,
    name_output: &[u8],
    gid_status: i32,
    gid_output: &[u8],
    name: &str,
    gid: u32,
) -> Result<GroupObservation, InstallerError> {
    if name_status == 2 && name_output.is_empty() && gid_status == 2 && gid_output.is_empty() {
        return Ok(GroupObservation::Absent);
    }
    let expected = format!("{name}:x:{gid}:\n");
    if name_status == 0
        && gid_status == 0
        && name_output == expected.as_bytes()
        && gid_output == expected.as_bytes()
    {
        return Ok(GroupObservation::Exact);
    }
    Err(InstallerError::HostPreflightFailure)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    #[test]
    fn group_selection_and_observation_are_exact_and_fail_closed() {
        assert_eq!(
            select_group_gid(
                b"root:x:0:\ndaemon:x:1:\nunrelated:x:998:member\n",
                b"root:x:0:0:root:/root:/bin/sh\nservice:x:1:999::/:/usr/sbin/nologin\n",
            )
            .unwrap(),
            997
        );
        assert!(select_group_gid(b"malformed\n", b"root:x:0:0:root:/root:/bin/sh\n").is_err());

        let exact = b"kapsel:x:999:\n";
        assert_eq!(
            classify_group_observation(0, exact, 0, exact, "kapsel", 999).unwrap(),
            GroupObservation::Exact
        );
        let callers = b"kapsel-service-callers:x:998:\n";
        assert_eq!(
            classify_group_observation(0, callers, 0, callers, "kapsel-service-callers", 998,)
                .unwrap(),
            GroupObservation::Exact
        );
        assert_eq!(
            classify_group_observation(2, b"", 2, b"", "kapsel", 999).unwrap(),
            GroupObservation::Absent
        );
        for (name_status, name, gid_status, gid) in [
            (0, exact.as_slice(), 2, b"".as_slice()),
            (0, b"kapsel:x:998:\n".as_slice(), 0, exact.as_slice()),
            (0, b"other:x:999:\n".as_slice(), 0, exact.as_slice()),
            (0, b"kapsel:x:999:member\n".as_slice(), 0, exact.as_slice()),
            (
                0,
                b"kapsel:x:999:\nextra:x:1:\n".as_slice(),
                0,
                exact.as_slice(),
            ),
        ] {
            assert!(
                classify_group_observation(name_status, name, gid_status, gid, "kapsel", 999)
                    .is_err()
            );
        }
    }

    #[test]
    fn user_selection_is_bounded_and_fail_closed() {
        assert_eq!(
            select_user_uid(
                b"root:x:0:0:root:/root:/bin/sh\nservice:x:998:999::/:/usr/sbin/nologin\n",
            )
            .unwrap(),
            999
        );
        assert!(select_user_uid(b"malformed\n").is_err());
        let mut exhausted = String::new();
        for uid in 101..=999 {
            writeln!(exhausted, "u{uid}:x:{uid}:1::/:/usr/sbin/nologin").unwrap();
        }
        assert!(select_user_uid(exhausted.as_bytes()).is_err());
    }

    #[test]
    fn user_observation_covers_all_four_classifications() {
        let user = UserResource {
            gecos_transaction_id: "88".repeat(32),
            home: String::from("/var/lib/kapsel"),
            kind: UserResourceKind::User,
            locked: true,
            name: String::from("kapsel"),
            primary_gid: 999,
            shell: String::from("/usr/sbin/nologin"),
            uid: 997,
        };
        let output = |status, bytes: &[u8]| BoundedCommandOutput {
            status,
            stdout: bytes.to_vec(),
        };
        let passwd = format!(
            "kapsel:x:997:999:{}:/var/lib/kapsel:/usr/sbin/nologin\n",
            user.gecos_transaction_id
        );
        let shadow = b"kapsel:!:20600::::::\n";
        let classify = |name: BoundedCommandOutput,
                        uid: BoundedCommandOutput,
                        shadow: BoundedCommandOutput| {
            classify_user_observation(&name, &uid, &shadow, &user)
        };

        assert_eq!(
            classify(
                output(0, passwd.as_bytes()),
                output(0, passwd.as_bytes()),
                output(0, shadow),
            ),
            UserObservation::Exact
        );
        assert_eq!(
            classify(output(2, b""), output(2, b""), output(2, b"")),
            UserObservation::Absent
        );

        for (name, uid, shadow) in [
            (
                output(
                    0,
                    b"kapsel:x:996:999:other:/var/lib/kapsel:/usr/sbin/nologin\n",
                ),
                output(2, b""),
                output(2, b""),
            ),
            (
                output(2, b""),
                output(0, b"other:x:997:999:other:/:/usr/sbin/nologin\n"),
                output(2, b""),
            ),
            (
                output(0, b"kapsel:x:997:999:other:/wrong:/usr/sbin/nologin\n"),
                output(0, b"kapsel:x:997:999:other:/wrong:/usr/sbin/nologin\n"),
                output(0, shadow),
            ),
        ] {
            assert_eq!(classify(name, uid, shadow), UserObservation::Conflict);
        }

        for (name, uid, shadow) in [
            (output(0, passwd.as_bytes()), output(2, b""), output(2, b"")),
            (
                output(0, passwd.as_bytes()),
                output(0, passwd.as_bytes()),
                output(2, b""),
            ),
            (
                output(0, passwd.as_bytes()),
                output(0, passwd.as_bytes()),
                output(0, b"kapsel:*:20600::::::\n"),
            ),
            (
                output(0, passwd.as_bytes()),
                output(0, passwd.as_bytes()),
                output(0, b"kapsel:!:not-a-day::::::\n"),
            ),
            (
                output(
                    0,
                    b"kapsel:x:997:999:unterminated:/var/lib/kapsel:/usr/sbin/nologin",
                ),
                output(0, passwd.as_bytes()),
                output(0, shadow),
            ),
            (
                output(0, b"malformed\n"),
                output(0, passwd.as_bytes()),
                output(0, shadow),
            ),
            (
                output(124, b""),
                output(0, passwd.as_bytes()),
                output(0, shadow),
            ),
            (output(2, b"unexpected"), output(2, b""), output(2, b"")),
        ] {
            assert_eq!(classify(name, uid, shadow), UserObservation::Ambiguous);
        }
    }
}
