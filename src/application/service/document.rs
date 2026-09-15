//! Strict bounded operator input, independent of filesystem and execution availability.

use std::{fmt, marker::PhantomData, path::PathBuf};

use serde::{
    de::{value::MapAccessDeserializer, Error as _, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};

use super::{ServiceApproval, ServiceConfiguration, ServiceError};

/// Structurally bounded service configuration and its public receipt signer identity.
///
/// Application opening must authenticate grants and validate retained identity before use.
pub struct ServiceOperatorDocument {
    /// Operator approvals and separately appointed historical keys.
    pub configuration: ServiceConfiguration,
    /// Public identity for optional receipt signing material, not a signing seed.
    pub receipt_signing_key_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    service_configuration_version: u8,
    authorization_keys: BoundedVec<MapOnly<Key>, 128>,
    approvals: BoundedVec<MapOnly<Approval>, 32>,
    receipt_signing_key_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Key {
    key_id: String,
    public_key_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    label: String,
    signed_grant_hex: String,
}

/// Parses only the versioned service document, with no file or receiver access.
///
/// The caller supplies the already confined journal path. Bytes never select a private path.
///
/// # Errors
///
/// Rejects malformed, unversioned, oversized or out-of-grammar input with one bounded error.
pub fn parse_service_operator_document(
    bytes: &[u8],
    journal_path: PathBuf,
) -> Result<ServiceOperatorDocument, ServiceError> {
    if bytes.is_empty() || bytes.len() > 160 * 1024 {
        return Err(ServiceError::Configuration);
    }
    let MapOnly(document): MapOnly<Document> =
        serde_json::from_slice(bytes).map_err(|_| ServiceError::Configuration)?;
    if document.service_configuration_version != 1 {
        return Err(ServiceError::Configuration);
    }
    crate::gateway::validate_key_id(&document.receipt_signing_key_id)
        .map_err(|_| ServiceError::Configuration)?;
    let authorization_trust = document
        .authorization_keys
        .0
        .into_iter()
        .map(|MapOnly(key)| {
            let public_key: [u8; 32] = decode_hex(&key.public_key_hex, 32)?
                .try_into()
                .map_err(|_| ServiceError::Configuration)?;
            let trust = crate::AuthorizationTrust {
                key_id: key.key_id,
                public_key,
            };
            crate::gateway::validate_authorization_trust(&trust)
                .map_err(|_| ServiceError::Configuration)?;
            Ok(trust)
        })
        .collect::<Result<Vec<_>, ServiceError>>()?;
    let approvals = document
        .approvals
        .0
        .into_iter()
        .map(|MapOnly(approval)| {
            if approval.label.len() > 128
                || !approval
                    .label
                    .bytes()
                    .all(|byte| (32..=126).contains(&byte))
            {
                return Err(ServiceError::Configuration);
            }
            Ok(ServiceApproval {
                label: approval.label,
                signed_grant: decode_hex(&approval.signed_grant_hex, 4096)?,
            })
        })
        .collect::<Result<Vec<_>, ServiceError>>()?;
    Ok(ServiceOperatorDocument {
        configuration: ServiceConfiguration {
            journal_path,
            authorization_trust,
            approvals,
        },
        receipt_signing_key_id: document.receipt_signing_key_id,
    })
}

fn decode_hex(text: &str, maximum: usize) -> Result<Vec<u8>, ServiceError> {
    if text.is_empty()
        || text.len() > maximum * 2
        || !text.len().is_multiple_of(2)
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ServiceError::Configuration);
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|_| ServiceError::Configuration)?;
            u8::from_str_radix(pair, 16).map_err(|_| ServiceError::Configuration)
        })
        .collect()
}

// Derived structs also accept positional sequences. Only maps may reach those decoders here.
struct MapOnly<T>(T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for MapOnly<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MapVisitor<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for MapVisitor<T> {
            type Value = MapOnly<T>;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object with named fields")
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                T::deserialize(MapAccessDeserializer::new(map)).map(MapOnly)
            }
        }
        deserializer.deserialize_map(MapVisitor::<T>(PhantomData))
    }
}

// Two bounded arrays share this private decoder. It never parses or allocates an extra element.
struct BoundedVec<T, const MAX: usize>(Vec<T>);
impl<'de, T: Deserialize<'de>, const MAX: usize> Deserialize<'de> for BoundedVec<T, MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BoundedVisitor<T, const MAX: usize>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for BoundedVisitor<T, MAX> {
            type Value = BoundedVec<T, MAX>;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "an array with at most {MAX} entries")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while values.len() < MAX {
                    let Some(value) = sequence.next_element()? else {
                        return Ok(BoundedVec(values));
                    };
                    values.push(value);
                }
                let _ = sequence.next_element::<RejectExtra>()?;
                Ok(BoundedVec(values))
            }
        }
        deserializer.deserialize_seq(BoundedVisitor::<T, MAX>(PhantomData))
    }
}

struct RejectExtra;
impl<'de> Deserialize<'de> for RejectExtra {
    fn deserialize<D: Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
        Err(D::Error::custom("service array capacity exceeded"))
    }
}

#[cfg(test)]
mod tests {
    use super::BoundedVec;

    #[test]
    #[allow(clippy::unwrap_used, reason = "controlled parser regression")]
    fn overflow_is_rejected_before_deserializing_the_extra_element() {
        assert!(serde_json::from_slice::<BoundedVec<u8, 1>>(b"[]").is_ok());
        assert!(serde_json::from_slice::<BoundedVec<u8, 1>>(b"[1]").is_ok());
        let error = serde_json::from_slice::<BoundedVec<u8, 1>>(b"[1,{not valid json")
            .err()
            .unwrap();
        assert!(error
            .to_string()
            .contains("service array capacity exceeded"));
    }
}
