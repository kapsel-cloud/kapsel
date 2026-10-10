//! Fixed-purpose authority for an exact transition of the operator's prepared Git branch.

use ed25519_dalek::{Signature, VerifyingKey};

use super::{
    digest_hex, identity_is_valid, record, sign_grant_statement, signature_input,
    AuthorizationGrantError, AuthorizationTrust,
};

const STATEMENT_MAGIC: &[u8] = b"KAPSEL-GIT-REF-GRANT-STATEMENT-V1\0";
const GRANT_MAGIC: &[u8] = b"KAPSEL-GIT-REF-GRANT-V1\0";
const PURPOSE: &str = "kapsel.git-ref-transition-grant.v1";
const STATEMENT_MAX: usize = 2048;
const GRANT_MAX: usize = 4096;

/// The sole branch accepted by the fixed local Git receiver.
pub const APPROVED_GIT_REF: &str = "refs/heads/approved";

/// Exact public facts approved for one Git transition, without paths or transport authority.
///
/// Repository identity is an operator-managed label, not a pathname discovered from the grant.
/// Preparation, repository custody, commit types and ancestry require separate receiver checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitRefAuthorization {
    /// Stable authorization identity, using the bounded operation-identity grammar.
    pub authorization_id: String,
    /// Stable operation identity, bound to these exact bytes across recovery.
    pub operation_id: String,
    /// Exact operator-managed repository identity.
    pub repository_id: String,
    /// Fixed full branch name, exactly [`APPROVED_GIT_REF`].
    pub reference: String,
    /// Expected old commit, a full lowercase SHA-1 object ID.
    pub old_commit: String,
    /// Prepared descendant commit, a distinct full lowercase SHA-1 object ID.
    pub new_commit: String,
}

impl GitRefAuthorization {
    /// Validates only bounded statement grammar, not repository contents or custody.
    pub fn is_valid(&self) -> bool {
        [
            &self.authorization_id,
            &self.operation_id,
            &self.repository_id,
        ]
        .into_iter()
        .all(|value| identity_is_valid(value))
            && self.reference == APPROVED_GIT_REF
            && git_commit_id_is_valid(&self.old_commit)
            && git_commit_id_is_valid(&self.new_commit)
            && self.old_commit != self.new_commit
    }
}

/// Tests the fixed receiver's full lowercase, nonzero SHA-1 object-ID grammar.
///
/// This does not establish that an object exists or is a commit. SHA-256 repositories are not
/// accepted by this version of the capability.
pub fn git_commit_id_is_valid(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        && value.bytes().any(|byte| byte != b'0')
}

/// Git authority authenticated under separately configured trust.
///
/// Fields are private so callers cannot construct authenticated provenance from unsigned input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedGitRefGrant {
    authorization: GitRefAuthorization,
    signer_key_id: String,
    grant_digest: String,
}

impl ValidatedGitRefGrant {
    /// Consumes the grant into its approval, signer key ID and lowercase SHA-256 grant digest.
    ///
    /// These facts retain the original trust appointment. They do not appoint a new one.
    pub fn into_parts(self) -> (GitRefAuthorization, String, String) {
        (self.authorization, self.signer_key_id, self.grant_digest)
    }
}

/// Signs one bounded Git approval with a purpose distinct from all Kubernetes grant versions.
///
/// # Errors
///
/// Rejects invalid statement grammar or signing-key identity. It does not read a repository.
pub fn sign_git_ref_grant(
    authorization: &GitRefAuthorization,
    signing_seed: &[u8; 32],
    key_id: &str,
) -> Result<Vec<u8>, AuthorizationGrantError> {
    if !authorization.is_valid() || !identity_is_valid(key_id) {
        return Err(AuthorizationGrantError::Invalid);
    }

    let mut statement = STATEMENT_MAGIC.to_vec();
    for (tag, value) in (1..=6).zip([
        &authorization.authorization_id,
        &authorization.operation_id,
        &authorization.repository_id,
        &authorization.reference,
        &authorization.old_commit,
        &authorization.new_commit,
    ]) {
        append_grant_record(&mut statement, tag, value.as_bytes(), STATEMENT_MAX)?;
    }
    sign_grant_statement(&statement, GRANT_MAGIC, PURPOSE, signing_seed, key_id)
}

/// Verifies at most 4 KiB of canonical Git grant bytes under a separately appointed signer and key.
///
/// A valid signature authenticates the exact approval, not commit contents, ancestry, repository
/// custody or execution. Receiver checks remain separate. This function performs no repository I/O.
///
/// # Errors
///
/// Rejects oversized, malformed, noncanonical, wrong-purpose or unauthenticated bytes, and invalid
/// trust appointments.
pub fn verify_git_ref_grant(
    bytes: &[u8],
    trust: &AuthorizationTrust,
) -> Result<ValidatedGitRefGrant, AuthorizationGrantError> {
    trust.validate()?;
    if bytes.len() > GRANT_MAX {
        return Err(AuthorizationGrantError::Invalid);
    }

    let mut envelope = record::Records::new(bytes, GRANT_MAGIC).map_err(map_frame_error)?;
    if envelope.take(1).map_err(map_frame_error)? != PURPOSE.as_bytes() {
        return Err(AuthorizationGrantError::Invalid);
    }
    let key_id = decode_bounded_ascii(envelope.take(2).map_err(map_frame_error)?, 128)?;
    if !identity_is_valid(&key_id) {
        return Err(AuthorizationGrantError::Invalid);
    }
    let statement = envelope.take(3).map_err(map_frame_error)?;
    if statement.len() > STATEMENT_MAX {
        return Err(AuthorizationGrantError::Invalid);
    }
    let signature: [u8; 64] = envelope
        .take(4)
        .map_err(map_frame_error)?
        .try_into()
        .map_err(|_| AuthorizationGrantError::Invalid)?;
    envelope.finish().map_err(map_frame_error)?;

    let mut fields = record::Records::new(statement, STATEMENT_MAGIC).map_err(map_frame_error)?;
    let authorization = GitRefAuthorization {
        authorization_id: decode_bounded_ascii(fields.take(1).map_err(map_frame_error)?, 128)?,
        operation_id: decode_bounded_ascii(fields.take(2).map_err(map_frame_error)?, 128)?,
        repository_id: decode_bounded_ascii(fields.take(3).map_err(map_frame_error)?, 128)?,
        reference: decode_bounded_ascii(
            fields.take(4).map_err(map_frame_error)?,
            APPROVED_GIT_REF.len(),
        )?,
        old_commit: decode_bounded_ascii(fields.take(5).map_err(map_frame_error)?, 40)?,
        new_commit: decode_bounded_ascii(fields.take(6).map_err(map_frame_error)?, 40)?,
    };
    fields.finish().map_err(map_frame_error)?;
    if !authorization.is_valid() {
        return Err(AuthorizationGrantError::Invalid);
    }

    if key_id != trust.key_id {
        return Err(AuthorizationGrantError::Untrusted);
    }
    VerifyingKey::from_bytes(&trust.public_key)
        .map_err(|_| AuthorizationGrantError::Invalid)?
        .verify_strict(
            &signature_input(PURPOSE, statement),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| AuthorizationGrantError::Untrusted)?;

    Ok(ValidatedGitRefGrant {
        authorization,
        signer_key_id: key_id,
        grant_digest: digest_hex(bytes),
    })
}

fn decode_bounded_ascii(
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<String, AuthorizationGrantError> {
    if bytes.len() > maximum_bytes || !bytes.is_ascii() {
        return Err(AuthorizationGrantError::Invalid);
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| AuthorizationGrantError::Invalid)
}

fn append_grant_record(
    output: &mut Vec<u8>,
    tag: u8,
    value: &[u8],
    maximum_bytes: usize,
) -> Result<(), AuthorizationGrantError> {
    record::push(output, tag, value, maximum_bytes).map_err(map_frame_error)
}

fn map_frame_error(_: record::FrameError) -> AuthorizationGrantError {
    AuthorizationGrantError::Invalid
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::{ApprovedTarget, ExactAuthorization};

    fn approval() -> GitRefAuthorization {
        GitRefAuthorization {
            authorization_id: "approval-1".into(),
            operation_id: "operation-1".into(),
            repository_id: "repository-1".into(),
            reference: APPROVED_GIT_REF.into(),
            old_commit: "a".repeat(40),
            new_commit: "b".repeat(40),
        }
    }

    fn trust() -> AuthorizationTrust {
        AuthorizationTrust {
            key_id: "git-owner".into(),
            public_key: SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        }
    }

    #[test]
    fn exact_authority_round_trips_with_original_provenance() {
        let original = approval();
        let bytes = sign_git_ref_grant(&original, &[7; 32], "git-owner").unwrap();

        let (actual, signer, digest) = verify_git_ref_grant(&bytes, &trust()).unwrap().into_parts();

        assert_eq!(actual, original);
        assert_eq!(signer, "git-owner");
        assert_eq!(digest, digest_hex(&bytes));
        assert_eq!(
            digest,
            "c264a2a3c342f2dfff1c5ba5fbda1966f8471aef04516af51106d38dabe76d38"
        );
        assert_eq!(
            bytes,
            sign_git_ref_grant(&actual, &[7; 32], &signer).unwrap()
        );
    }

    #[test]
    fn every_statement_field_and_signature_is_authenticated() {
        let bytes = sign_git_ref_grant(&approval(), &[7; 32], "git-owner").unwrap();
        for needle in [
            "approval-1",
            "operation-1",
            "repository-1",
            APPROVED_GIT_REF,
            &"a".repeat(40),
            &"b".repeat(40),
        ] {
            let mut changed = bytes.clone();
            let position = changed
                .windows(needle.len())
                .position(|window| window == needle.as_bytes())
                .unwrap();
            changed[position] ^= 1;
            assert!(
                verify_git_ref_grant(&changed, &trust()).is_err(),
                "{needle}"
            );
        }

        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(matches!(
            verify_git_ref_grant(&changed, &trust()),
            Err(AuthorizationGrantError::Untrusted)
        ));

        let mut wrong_identity = trust();
        wrong_identity.key_id = "another-owner".into();
        assert!(matches!(
            verify_git_ref_grant(&bytes, &wrong_identity),
            Err(AuthorizationGrantError::Untrusted)
        ));

        let mut wrong_key = trust();
        wrong_key.public_key = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        assert!(matches!(
            verify_git_ref_grant(&bytes, &wrong_key),
            Err(AuthorizationGrantError::Untrusted)
        ));
    }

    #[test]
    fn malformed_framing_and_oversize_inputs_fail_closed() {
        let bytes = sign_git_ref_grant(&approval(), &[7; 32], "git-owner").unwrap();
        for length in 0..bytes.len() {
            assert!(verify_git_ref_grant(&bytes[..length], &trust()).is_err());
        }

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(verify_git_ref_grant(&trailing, &trust()).is_err());

        let mut oversized = bytes.clone();
        oversized.resize(GRANT_MAX + 1, 0);
        assert!(verify_git_ref_grant(&oversized, &trust()).is_err());

        let mut reordered = bytes.clone();
        reordered[GRANT_MAGIC.len()] = 2;
        assert!(verify_git_ref_grant(&reordered, &trust()).is_err());

        let mut hostile_length = bytes;
        hostile_length[GRANT_MAGIC.len() + 1..GRANT_MAGIC.len() + 5]
            .copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(verify_git_ref_grant(&hostile_length, &trust()).is_err());
    }

    #[test]
    fn authority_cannot_supply_paths_flags_other_refs_or_abbreviated_objects() {
        for invalid in [
            "",
            "../repo",
            "file:///tmp/repo",
            "--upload-pack=x",
            "x y",
            &"x".repeat(129),
        ] {
            let mut value = approval();
            value.repository_id = invalid.into();
            assert!(sign_git_ref_grant(&value, &[7; 32], "git-owner").is_err());
        }

        for invalid in [
            "approved",
            "refs/heads/main",
            "+refs/heads/approved",
            "refs/heads/approved\n",
        ] {
            let mut value = approval();
            value.reference = invalid.into();
            assert!(sign_git_ref_grant(&value, &[7; 32], "git-owner").is_err());
        }

        for invalid in [
            "",
            "HEAD",
            &"a".repeat(39),
            &"a".repeat(41),
            &"a".repeat(64),
            &"A".repeat(40),
            &"0".repeat(40),
            &"g".repeat(40),
        ] {
            assert!(!git_commit_id_is_valid(invalid));
            for replace_old_commit in [false, true] {
                let mut value = approval();
                if replace_old_commit {
                    value.old_commit = invalid.into();
                } else {
                    value.new_commit = invalid.into();
                }
                assert!(sign_git_ref_grant(&value, &[7; 32], "git-owner").is_err());
            }
        }

        let mut noop = approval();
        noop.new_commit.clone_from(&noop.old_commit);
        assert!(sign_git_ref_grant(&noop, &[7; 32], "git-owner").is_err());
    }

    #[test]
    fn git_and_kubernetes_grants_cannot_cross_purposes() {
        let git = sign_git_ref_grant(&approval(), &[7; 32], "git-owner").unwrap();
        assert!(crate::verify_authorization_grant(&git, &trust()).is_err());
        let mut kubernetes = ExactAuthorization {
            approved_target: None,
            authorization_id: "approval-1".into(),
            operation_id: "operation-1".into(),
            namespace: "default".into(),
            deployment: "app".into(),
            container: "app".into(),
            immutable_image_digest: format!("app@sha256:{}", "a".repeat(64)),
        };
        for snapshot in [
            None,
            Some(ApprovedTarget {
                uid: "uid-1".into(),
                resource_version: "1".into(),
            }),
        ] {
            kubernetes.approved_target = snapshot;
            let bytes =
                crate::sign_authorization_grant(&kubernetes, &[7; 32], "git-owner").unwrap();
            assert!(verify_git_ref_grant(&bytes, &trust()).is_err());
            assert!(crate::verify_authorization_grant(&bytes, &trust()).is_ok());
        }
    }
}
