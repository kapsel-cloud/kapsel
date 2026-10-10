//! Canonical Git evidence, separate from Kubernetes receipt purposes and classifiers.

use kapsel_authority::GitRefAuthorization;

use super::{
    bounded, parse_envelope, push, push_text, sign_envelope, validate_digest, validate_key_id,
    InspectionLimits, InspectionStatus, ReceiptEnvelope, ReceiptError, ReceiptTrust, Records,
    STATEMENT_BYTES_MAX,
};
use crate::gateway::{
    git::{Acknowledgement, ObservedRef},
    OperationResult,
};

const STATEMENT_MAGIC: &[u8] = b"KAPSEL-GIT-REF-STATEMENT-V1\0";
const RECEIPT_MAGIC: &[u8] = b"KAPSEL-GIT-REF-RECEIPT-V1\0";
/// Fixed signing purpose for Git transition receipts.
pub const PURPOSE: &str = "kapsel.git-ref-transition-receipt.v1";
const NON_CLAIMS: &str = concat!(
    "no-hook-delivery;no-ci;no-deployment;",
    "no-complete-capture;no-witnessing;not-production",
);

/// Read-only Git statement containing approval, acknowledgement and observation facts.
///
/// The result follows the retained acknowledgement, not the observed ref. Use
/// [`GitInspectionReport::status`] to check authentication and trust acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitStatement {
    pub(in crate::gateway) authorization: GitRefAuthorization,
    pub(in crate::gateway) authorization_signer: String,
    pub(in crate::gateway) authorization_digest: String,
    pub(in crate::gateway) acknowledgement: Acknowledgement,
    pub(in crate::gateway) observed: ObservedRef,
}

impl GitStatement {
    /// Original exact approval, including operation and repository identities.
    pub fn authorization(&self) -> &GitRefAuthorization {
        &self.authorization
    }

    /// Public identity of the externally appointed authorization signer.
    pub fn authorization_signer_key_id(&self) -> &str {
        &self.authorization_signer
    }

    /// SHA-256 of the original signed grant bytes.
    pub fn authorization_grant_digest(&self) -> &str {
        &self.authorization_digest
    }

    /// Original per-ref acknowledgement, never inferred from the current ref.
    pub fn acknowledgement(&self) -> Acknowledgement {
        self.acknowledgement
    }

    /// Frozen present-ref observation, not proof of who changed the ref.
    pub fn observed_ref(&self) -> &ObservedRef {
        &self.observed
    }

    /// Attribution of the acknowledged original transition, not of later observed state.
    pub fn attribution(&self) -> &'static str {
        if self.acknowledgement == Acknowledgement::Updated {
            "acknowledged_update"
        } else {
            "not_established"
        }
    }

    /// Fixed limits on what this receipt establishes.
    pub fn non_claims() -> &'static str {
        NON_CLAIMS
    }

    /// Ref-transition result derived solely from the retained per-ref acknowledgement.
    pub fn result(&self) -> OperationResult {
        match self.acknowledgement {
            Acknowledgement::Updated => OperationResult::Succeeded,
            Acknowledgement::RejectedBeforeSend | Acknowledgement::ReceiverRejected => {
                OperationResult::Failed
            },
            Acknowledgement::Unknown => OperationResult::Unknown,
        }
    }

    fn encode(&self) -> Result<Vec<u8>, ReceiptError> {
        if !self.authorization.is_valid() {
            return Err(ReceiptError::InvalidValue);
        }
        validate_key_id(&self.authorization_signer)?;
        validate_digest(&self.authorization_digest)?;
        let (observed_kind, observed_commit) = match &self.observed {
            ObservedRef::Commit(commit) if kapsel_authority::git_commit_id_is_valid(commit) => {
                ("commit", commit.as_str())
            },
            ObservedRef::Commit(_) => return Err(ReceiptError::InvalidValue),
            ObservedRef::Missing => ("missing", ""),
            ObservedRef::Unknown => ("unknown", ""),
        };
        let acknowledgement = self.acknowledgement.as_str();
        let attribution = self.attribution();
        let result = match self.result() {
            OperationResult::Succeeded => "SUCCEEDED",
            OperationResult::Failed => "FAILED",
            OperationResult::Unknown => "UNKNOWN",
        };

        let authorization = &self.authorization;
        let mut bytes = STATEMENT_MAGIC.to_vec();
        for (tag, value) in (1..=15).zip([
            authorization.operation_id.as_str(),
            &authorization.authorization_id,
            &self.authorization_signer,
            &self.authorization_digest,
            &authorization.repository_id,
            &authorization.reference,
            &authorization.old_commit,
            &authorization.new_commit,
            "git-exact-lease",
            acknowledgement,
            observed_kind,
            observed_commit,
            attribution,
            result,
            NON_CLAIMS,
        ]) {
            if tag == 12 {
                push(&mut bytes, tag, value.as_bytes(), STATEMENT_BYTES_MAX)?;
            } else {
                push_text(&mut bytes, tag, value, STATEMENT_BYTES_MAX)?;
            }
        }
        Ok(bytes)
    }

    fn parse(bytes: &[u8], limits: InspectionLimits) -> Result<Self, ReceiptError> {
        bounded(bytes, limits.statement_bytes_max)?;

        let mut records = Records::new(bytes, STATEMENT_MAGIC, limits.text_bytes_max)?;
        let operation_id = records.text(1)?;
        let authorization_id = records.text(2)?;
        let authorization_signer = records.text(3)?;
        let authorization_digest = records.text(4)?;
        let authorization = GitRefAuthorization {
            operation_id,
            authorization_id,
            repository_id: records.text(5)?,
            reference: records.text(6)?,
            old_commit: records.text(7)?,
            new_commit: records.text(8)?,
        };

        if records.text(9)? != "git-exact-lease" {
            return Err(ReceiptError::InvalidValue);
        }
        let acknowledgement =
            Acknowledgement::parse(&records.text(10)?).ok_or(ReceiptError::InvalidValue)?;
        let observed_kind = records.text(11)?;
        let observed_commit = records.text(12)?;
        let observed = match (observed_kind.as_str(), observed_commit.as_str()) {
            ("commit", _) if kapsel_authority::git_commit_id_is_valid(&observed_commit) => {
                ObservedRef::Commit(observed_commit)
            },
            ("missing", "") => ObservedRef::Missing,
            ("unknown", "") => ObservedRef::Unknown,
            _ => return Err(ReceiptError::InvalidValue),
        };

        let _encoded_attribution = records.text(13)?;
        let _encoded_result = records.text(14)?;
        let _encoded_non_claims = records.text(15)?;
        records.finish()?;

        let statement = Self {
            authorization,
            authorization_signer,
            authorization_digest,
            acknowledgement,
            observed,
        };
        // Re-encoding checks derived attribution/result, exact non-claims and canonical bytes.
        let canonical_statement = statement.encode()?;
        if canonical_statement != bytes {
            return Err(ReceiptError::InvalidValue);
        }
        Ok(statement)
    }
}

pub(in crate::gateway) fn sign(
    statement: &GitStatement,
    seed: &[u8; 32],
    key_id: &str,
) -> Result<Vec<u8>, ReceiptError> {
    validate_key_id(key_id)?;
    let statement = statement.encode()?;
    sign_envelope(&statement, RECEIPT_MAGIC, PURPOSE, seed, key_id)
}

fn envelope(
    bytes: &[u8],
    limits: InspectionLimits,
) -> Result<ReceiptEnvelope<'_, GitStatement>, ReceiptError> {
    parse_envelope(bytes, RECEIPT_MAGIC, PURPOSE, limits, |statement| {
        GitStatement::parse(statement, limits)
    })
}

pub(in crate::gateway) fn decode(bytes: &[u8]) -> Result<(String, GitStatement), ReceiptError> {
    let parsed = envelope(bytes, InspectionLimits::default())?;
    Ok((parsed.key_id, parsed.statement))
}

/// Bounded offline inspection result for Git transition evidence.
///
/// An authenticated statement can be present even when trust rejects the signer. Use
/// [`Self::status`] rather than statement presence to decide whether inspection succeeded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitInspectionReport {
    status: InspectionStatus,
    statement: Option<GitStatement>,
}

impl GitInspectionReport {
    /// Single acceptance decision under the supplied trust and evaluation time.
    pub fn status(&self) -> InspectionStatus {
        self.status
    }

    /// Authenticated facts, present for inspected or untrusted-signer reports only.
    pub fn statement(&self) -> Option<&GitStatement> {
        self.statement.as_ref()
    }
}

/// Inspects bounded Git receipt bytes under explicit trust, time and limits without I/O.
///
/// The caller supplies receipt bytes, trust bytes, evaluation time in Unix seconds and limits.
/// Invalid limits or rejected structure produce [`InspectionStatus::StructureRejected`].
///
/// Authentication establishes the signed account, not receiver truth, hook delivery, CI,
/// deployment or causation of a later observed ref. Kubernetes receipts use their own parser.
pub fn inspect_git_receipt(
    bytes: &[u8],
    trust: &[u8],
    time: i64,
    limits: InspectionLimits,
) -> GitInspectionReport {
    let (status, statement) = inspect(bytes, trust, time, limits);
    GitInspectionReport { status, statement }
}

fn inspect(
    bytes: &[u8],
    trust: &[u8],
    time: i64,
    limits: InspectionLimits,
) -> (InspectionStatus, Option<GitStatement>) {
    let Ok(envelope) = envelope(bytes, limits) else {
        return (InspectionStatus::StructureRejected, None);
    };
    let Ok(trust) = ReceiptTrust::parse(trust, limits) else {
        return (InspectionStatus::StructureRejected, None);
    };

    let status = match envelope.authenticate(&trust, time) {
        Ok(status) => status,
        Err(ReceiptError::BadSignature) => return (InspectionStatus::SignatureRejected, None),
        Err(_) => return (InspectionStatus::StructureRejected, None),
    };
    (status, Some(envelope.statement))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn statement(acknowledgement: Acknowledgement) -> GitStatement {
        GitStatement {
            authorization: GitRefAuthorization {
                authorization_id: "approval".into(),
                operation_id: "operation".into(),
                repository_id: "repository".into(),
                reference: kapsel_authority::APPROVED_GIT_REF.into(),
                old_commit: "a".repeat(40),
                new_commit: "b".repeat(40),
            },
            authorization_signer: "owner".into(),
            authorization_digest: "c".repeat(64),
            acknowledgement,
            observed: ObservedRef::Commit("b".repeat(40)),
        }
    }

    fn trust() -> ReceiptTrust {
        ReceiptTrust {
            key_id: "signer".into(),
            public_key: SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
            accepted_purpose: PURPOSE.into(),
            not_before_unix_s: 0,
            not_after_unix_s: 100,
        }
    }

    #[test]
    fn frozen_acknowledgement_not_present_ref_owns_result_and_attribution() {
        for (acknowledgement, expected_result) in [
            (Acknowledgement::Updated, OperationResult::Succeeded),
            (Acknowledgement::ReceiverRejected, OperationResult::Failed),
            (Acknowledgement::RejectedBeforeSend, OperationResult::Failed),
            (Acknowledgement::Unknown, OperationResult::Unknown),
        ] {
            let statement = statement(acknowledgement);
            let bytes = sign(&statement, &[7; 32], "signer").unwrap();
            if acknowledgement == Acknowledgement::Unknown {
                assert_eq!(
                    crate::gateway::receipt::publication::receipt_digest_hex(&bytes),
                    "92f6bcc78e348fbb9e92323603a24072b1c9479403e0f1c2c311be5c73e3a5a5"
                );
            }
            let (status, parsed) = inspect(
                &bytes,
                &trust().encode().unwrap(),
                50,
                InspectionLimits::default(),
            );

            assert_eq!(status, InspectionStatus::Inspected);
            assert_eq!(parsed.unwrap(), statement);
            assert_eq!(statement.result(), expected_result);
            assert_eq!(decode(&bytes).unwrap(), ("signer".into(), statement));
            assert_eq!(
                crate::gateway::receipt::inspect_receipt(
                    &bytes,
                    &trust().encode().unwrap(),
                    50,
                    InspectionLimits::default()
                )
                .status(),
                InspectionStatus::StructureRejected
            );
        }
    }

    #[test]
    fn hostile_and_untrusted_evidence_never_becomes_inspected() {
        let bytes = sign(&statement(Acknowledgement::Unknown), &[7; 32], "signer").unwrap();
        let trusted = trust().encode().unwrap();
        for length in 0..bytes.len() {
            assert_eq!(
                inspect(&bytes[..length], &trusted, 50, InspectionLimits::default()).0,
                InspectionStatus::StructureRejected
            );
        }

        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert_eq!(
            inspect(&changed, &trusted, 50, InspectionLimits::default()).0,
            InspectionStatus::SignatureRejected
        );

        for (purpose, key_id, time) in [
            (crate::gateway::receipt::PURPOSE, "signer", 50),
            (PURPOSE, "another-signer", 50),
            (PURPOSE, "signer", -1),
            (PURPOSE, "signer", 100),
        ] {
            let mut wrong = trust();
            wrong.accepted_purpose = purpose.into();
            wrong.key_id = key_id.into();
            let wrong = wrong.encode().unwrap();
            let (status, statement) = inspect(&bytes, &wrong, time, InspectionLimits::default());
            assert_eq!(status, InspectionStatus::UntrustedSigner);
            assert!(statement.is_some());
            assert_eq!(
                inspect(&changed, &wrong, time, InspectionLimits::default()).0,
                InspectionStatus::SignatureRejected
            );
        }
        assert_eq!(
            inspect(&bytes, &trusted, 0, InspectionLimits::default()).0,
            InspectionStatus::Inspected
        );
        changed = bytes;
        changed.push(0);
        assert_eq!(
            inspect(&changed, &trusted, 50, InspectionLimits::default()).0,
            InspectionStatus::StructureRejected
        );

        let encoded = statement(Acknowledgement::Unknown).encode().unwrap();
        let forged = String::from_utf8(encoded)
            .unwrap()
            .replace("not_established", "acknowledged_update");
        assert!(GitStatement::parse(forged.as_bytes(), InspectionLimits::default()).is_err());
    }
}
