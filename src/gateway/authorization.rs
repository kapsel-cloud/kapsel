//! Fixed-purpose signed authorization grants for the KAP-0038 experiment.
//!
//! This module is private to the one effect gateway. It is not a generic authorization SDK,
//! policy language, issuer model, or ambient trust mechanism.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use super::{validate_identity, ExactAuthorization, GatewayError, InputField};

const GRANT_STATEMENT_MAGIC: &[u8] = b"KAPSEL-KAP0038-K8S-GRANT-STATEMENT-V1\0";
const SIGNED_GRANT_MAGIC: &[u8] = b"KAPSEL-KAP0038-K8S-GRANT-V1\0";
const GRANT_PURPOSE: &str = "kapsel.kap0038.kubernetes-set-deployment-image-grant.v1";
const SIGNED_GRANT_BYTES_MAX: usize = 4 * 1024;
const GRANT_STATEMENT_BYTES_MAX: usize = 2 * 1024;
const GRANT_TEXT_BYTES_MAX: usize = 512;

/// Owner-controlled trust for the one fixed-purpose authorization-grant signer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationTrust {
    /// Exact configured grant signing-key identity.
    pub key_id: String,
    /// Exact configured Ed25519 verifying key.
    pub public_key: [u8; 32],
}

impl AuthorizationTrust {
    pub(super) fn validate(&self) -> Result<(), GatewayError> {
        validate_identity(InputField::AuthorizationId, &self.key_id)
            .map_err(|_| GatewayError::InvalidAuthorizationGrant)?;
        VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| GatewayError::InvalidAuthorizationGrant)?;
        Ok(())
    }
}

pub(crate) struct VerifiedAuthorization {
    pub(crate) authorization: ExactAuthorization,
    pub(crate) signer_key_id: String,
    pub(crate) grant_digest: String,
}

/// Produces canonical owner-signed bytes for one exact KAP-0038 authorization grant.
///
/// Signing is exposed for owner-side composition and deterministic vectors. Possessing this
/// function conveys no authority without the configured private signing seed.
pub(crate) fn sign_authorization_grant(
    authorization: &ExactAuthorization,
    signing_seed: &[u8; 32],
    key_id: &str,
) -> Result<Vec<u8>, GatewayError> {
    authorization.validate()?;
    validate_identity(InputField::AuthorizationId, key_id)
        .map_err(|_| GatewayError::InvalidAuthorizationGrant)?;
    let statement = encode_statement(authorization)?;
    let signature = SigningKey::from_bytes(signing_seed).sign(&signature_input(&statement));
    let mut output = Vec::with_capacity(statement.len() + 192);
    output.extend_from_slice(SIGNED_GRANT_MAGIC);
    push(
        &mut output,
        1,
        GRANT_PURPOSE.as_bytes(),
        SIGNED_GRANT_BYTES_MAX,
    )?;
    push(&mut output, 2, key_id.as_bytes(), SIGNED_GRANT_BYTES_MAX)?;
    push(&mut output, 3, &statement, SIGNED_GRANT_BYTES_MAX)?;
    push(
        &mut output,
        4,
        &signature.to_bytes(),
        SIGNED_GRANT_BYTES_MAX,
    )?;
    Ok(output)
}

pub(crate) fn verify_authorization_grant(
    bytes: &[u8],
    trust: &AuthorizationTrust,
) -> Result<VerifiedAuthorization, GatewayError> {
    trust.validate()?;
    if bytes.len() > SIGNED_GRANT_BYTES_MAX {
        return Err(GatewayError::InvalidAuthorizationGrant);
    }
    let mut records = Records::new(bytes, SIGNED_GRANT_MAGIC)?;
    if records.take(1)? != GRANT_PURPOSE.as_bytes() {
        return Err(GatewayError::InvalidAuthorizationGrant);
    }
    let key_id = records.text(2)?;
    validate_identity(InputField::AuthorizationId, &key_id)
        .map_err(|_| GatewayError::InvalidAuthorizationGrant)?;
    let statement_bytes = records.take(3)?;
    if statement_bytes.len() > GRANT_STATEMENT_BYTES_MAX {
        return Err(GatewayError::InvalidAuthorizationGrant);
    }
    let signature_bytes: [u8; 64] = records
        .take(4)?
        .try_into()
        .map_err(|_| GatewayError::InvalidAuthorizationGrant)?;
    records.finish()?;
    let authorization = parse_statement(statement_bytes)?;
    if key_id != trust.key_id {
        return Err(GatewayError::UntrustedAuthorizationGrant);
    }
    let key = VerifyingKey::from_bytes(&trust.public_key)
        .map_err(|_| GatewayError::InvalidAuthorizationGrant)?;
    key.verify_strict(
        &signature_input(statement_bytes),
        &Signature::from_bytes(&signature_bytes),
    )
    .map_err(|_| GatewayError::UntrustedAuthorizationGrant)?;
    Ok(VerifiedAuthorization {
        authorization,
        signer_key_id: key_id,
        grant_digest: digest_hex(bytes),
    })
}

fn encode_statement(authorization: &ExactAuthorization) -> Result<Vec<u8>, GatewayError> {
    let mut output = Vec::with_capacity(768);
    output.extend_from_slice(GRANT_STATEMENT_MAGIC);
    for (tag, value) in [
        (1, authorization.authorization_id.as_str()),
        (2, authorization.operation_id.as_str()),
        (3, authorization.namespace.as_str()),
        (4, authorization.deployment.as_str()),
        (5, authorization.container.as_str()),
        (6, authorization.immutable_image_digest.as_str()),
    ] {
        push(
            &mut output,
            tag,
            value.as_bytes(),
            GRANT_STATEMENT_BYTES_MAX,
        )?;
    }
    Ok(output)
}

fn parse_statement(bytes: &[u8]) -> Result<ExactAuthorization, GatewayError> {
    let mut records = Records::new(bytes, GRANT_STATEMENT_MAGIC)?;
    let authorization = ExactAuthorization {
        authorization_id: records.text(1)?,
        operation_id: records.text(2)?,
        namespace: records.text(3)?,
        deployment: records.text(4)?,
        container: records.text(5)?,
        immutable_image_digest: records.text(6)?,
    };
    records.finish()?;
    authorization.validate()?;
    Ok(authorization)
}

fn signature_input(statement: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(GRANT_PURPOSE.len() + 1 + statement.len());
    input.extend_from_slice(GRANT_PURPOSE.as_bytes());
    input.push(0);
    input.extend_from_slice(statement);
    input
}

fn push(
    output: &mut Vec<u8>,
    tag: u8,
    value: &[u8],
    maximum_bytes: usize,
) -> Result<(), GatewayError> {
    let length = u32::try_from(value.len()).map_err(|_| GatewayError::InvalidAuthorizationGrant)?;
    if output
        .len()
        .checked_add(5)
        .and_then(|length| length.checked_add(value.len()))
        .is_none_or(|length| length > maximum_bytes)
    {
        return Err(GatewayError::InvalidAuthorizationGrant);
    }
    output.push(tag);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

struct Records<'a> {
    bytes: &'a [u8],
    offset: usize,
    next_tag: u8,
}

impl<'a> Records<'a> {
    fn new(bytes: &'a [u8], magic: &[u8]) -> Result<Self, GatewayError> {
        if !bytes.starts_with(magic) {
            return Err(GatewayError::InvalidAuthorizationGrant);
        }
        Ok(Self {
            bytes,
            offset: magic.len(),
            next_tag: 1,
        })
    }

    fn take(&mut self, expected_tag: u8) -> Result<&'a [u8], GatewayError> {
        if expected_tag != self.next_tag {
            return Err(GatewayError::InvalidAuthorizationGrant);
        }
        let header_end = self
            .offset
            .checked_add(5)
            .ok_or(GatewayError::InvalidAuthorizationGrant)?;
        if header_end > self.bytes.len() || self.bytes[self.offset] != expected_tag {
            return Err(GatewayError::InvalidAuthorizationGrant);
        }
        let length = u32::from_be_bytes(
            self.bytes[self.offset + 1..header_end]
                .try_into()
                .map_err(|_| GatewayError::InvalidAuthorizationGrant)?,
        );
        let length =
            usize::try_from(length).map_err(|_| GatewayError::InvalidAuthorizationGrant)?;
        let value_end = header_end
            .checked_add(length)
            .ok_or(GatewayError::InvalidAuthorizationGrant)?;
        if value_end > self.bytes.len() {
            return Err(GatewayError::InvalidAuthorizationGrant);
        }
        self.offset = value_end;
        self.next_tag = self
            .next_tag
            .checked_add(1)
            .ok_or(GatewayError::InvalidAuthorizationGrant)?;
        Ok(&self.bytes[header_end..value_end])
    }

    fn text(&mut self, expected_tag: u8) -> Result<String, GatewayError> {
        let value = self.take(expected_tag)?;
        if value.is_empty() || value.len() > GRANT_TEXT_BYTES_MAX || !value.is_ascii() {
            return Err(GatewayError::InvalidAuthorizationGrant);
        }
        String::from_utf8(value.to_vec()).map_err(|_| GatewayError::InvalidAuthorizationGrant)
    }

    fn finish(self) -> Result<(), GatewayError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(GatewayError::InvalidAuthorizationGrant)
        }
    }
}

fn digest_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").unwrap_or_else(|_| unreachable!());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorization() -> ExactAuthorization {
        ExactAuthorization {
            authorization_id: "auth-001".into(),
            operation_id: "op-001".into(),
            namespace: "demo".into(),
            deployment: "agent-api".into(),
            container: "api".into(),
            immutable_image_digest: concat!(
                "registry.example/example/agent-api@sha256:",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .into(),
        }
    }

    fn trust(seed: &[u8; 32], key_id: &str) -> AuthorizationTrust {
        AuthorizationTrust {
            key_id: key_id.into(),
            public_key: SigningKey::from_bytes(seed).verifying_key().to_bytes(),
        }
    }

    #[test]
    fn exact_owner_signed_grant_authenticates_under_application_configured_trust() {
        let seed = [7_u8; 32];
        let bytes = sign_authorization_grant(&authorization(), &seed, "owner-key").unwrap();
        let verified = verify_authorization_grant(&bytes, &trust(&seed, "owner-key")).unwrap();
        assert_eq!(verified.authorization, authorization());
        assert_eq!(verified.signer_key_id, "owner-key");
        assert_eq!(verified.grant_digest.len(), 64);
    }

    #[test]
    fn self_asserted_wrong_key_and_hostile_shapes_fail_closed() {
        let seed = [7_u8; 32];
        let bytes = sign_authorization_grant(&authorization(), &seed, "owner-key").unwrap();
        assert!(matches!(
            verify_authorization_grant(&bytes, &trust(&[8_u8; 32], "owner-key")),
            Err(GatewayError::UntrustedAuthorizationGrant)
        ));
        assert!(matches!(
            verify_authorization_grant(&bytes, &trust(&seed, "other-key")),
            Err(GatewayError::UntrustedAuthorizationGrant)
        ));
        for hostile in [
            bytes[..bytes.len() - 1].to_vec(),
            [bytes.as_slice(), b"trailing"].concat(),
            vec![0_u8; SIGNED_GRANT_BYTES_MAX + 1],
        ] {
            assert!(matches!(
                verify_authorization_grant(&hostile, &trust(&seed, "owner-key")),
                Err(GatewayError::InvalidAuthorizationGrant)
            ));
        }
    }
}
