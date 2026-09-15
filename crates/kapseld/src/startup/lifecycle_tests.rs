//! Shared lease custody and retained-directory identity checks.
#![allow(
    clippy::used_underscore_binding,
    reason = "tests inspect the retained lease descriptor identity"
)]
use std::{
    fs,
    os::unix::{fs::PermissionsExt as _, net::UnixListener},
};

use super::*;

#[test]
fn hostile_lifecycle_leaves_fail_closed_before_authority() {
    for mutation in [
        "mode",
        "restrictive",
        "symlink",
        "hardlink",
        "directory",
        "socket",
        "length",
    ] {
        let root = tests::valid_root(&format!("lifecycle-{mutation}"));
        let path = root.join("var/lib/kapsel").join(LIFECYCLE_LOCK);
        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut socket = None;
        match mutation {
            "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap(),
            "restrictive" => fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap(),
            "symlink" => {
                fs::remove_file(&path).unwrap();
                std::os::unix::fs::symlink("missing", &path).unwrap();
            },
            "hardlink" => fs::hard_link(&path, path.with_extension("link")).unwrap(),
            "directory" => {
                fs::remove_file(&path).unwrap();
                fs::create_dir(&path).unwrap();
            },
            "socket" => {
                fs::remove_file(&path).unwrap();
                socket = Some(UnixListener::bind(&path).unwrap());
            },
            "length" => fs::write(&path, b"x").unwrap(),
            _ => unreachable!(),
        }
        assert!(InstallationRoots::open_at(&root).is_err(), "{mutation}");
        drop(socket);
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn lifecycle_rejects_foreign_owner_and_effective_group() {
    if !rustix::process::geteuid().is_root() {
        return;
    }
    for owner in [true, false] {
        let root = tests::valid_root(if owner {
            "lifecycle-owner"
        } else {
            "lifecycle-group"
        });
        let path = root.join("var/lib/kapsel").join(LIFECYCLE_LOCK);
        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        rustix::fs::chown(
            &path,
            owner.then_some(rustix::process::Uid::from_raw(1)),
            (!owner).then_some(rustix::process::Gid::from_raw(
                rustix::process::getegid().as_raw() + 1,
            )),
        )
        .unwrap();
        assert!(InstallationRoots::open_at(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn lifecycle_named_inode_substitution_is_rejected_and_lock_is_never_removed() {
    let root = tests::valid_root("lifecycle-substitution");
    let roots = InstallationRoots::open_at(&root).unwrap();
    let path = root.join("var/lib/kapsel").join(LIFECYCLE_LOCK);
    let retained = path.with_extension("retained");
    fs::rename(&path, &retained).unwrap();
    fs::write(&path, b"").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(require_private_identity(&roots.state, LIFECYCLE_LOCK, &roots._lease, 0).is_err());
    let old = File::open(&retained).unwrap();
    assert!(flock(&old, FlockOperation::NonBlockingLockExclusive).is_err());
    drop(roots);
    flock(&old, FlockOperation::NonBlockingLockExclusive).unwrap();
    assert!(path.exists());
    assert!(retained.exists());
    fs::remove_dir_all(root).unwrap();
}
