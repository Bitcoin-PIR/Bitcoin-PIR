//! Provider-local service scope identifiers.

use sha2::{Digest, Sha256};

use crate::codec::{expect_v1, Decoder};
use crate::{ServiceProtocolError, SERVICE_PROTOCOL_VERSION};

pub type ProviderId = [u8; 32];
pub type ScopeId = [u8; 32];

pub const PROVIDER_ID_DOMAIN: &[u8] = b"BitcoinPIR/provider-id/v1";
pub const SCOPE_ID_DOMAIN: &[u8] = b"BitcoinPIR/service-scope/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BackendId {
    DpfPirV1 = 1,
    HarmonyPirV2 = 2,
    OnionPirV1 = 3,
    TeeOramV1 = 4,
}

impl BackendId {
    pub(crate) fn decode(value: u8) -> Result<Self, ServiceProtocolError> {
        match value {
            1 => Ok(Self::DpfPirV1),
            2 => Ok(Self::HarmonyPirV2),
            3 => Ok(Self::OnionPirV1),
            4 => Ok(Self::TeeOramV1),
            value => Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "BackendId",
                value,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum WorkloadId {
    DpfEvaluateJobV1 = 1,
    HarmonyHintBundleV1 = 2,
    HarmonyQueryJobV1 = 3,
    OnionEvaluateJobV1 = 4,
    TeeOramQueryV1 = 5,
}

impl WorkloadId {
    pub(crate) fn decode(value: u8) -> Result<Self, ServiceProtocolError> {
        match value {
            1 => Ok(Self::DpfEvaluateJobV1),
            2 => Ok(Self::HarmonyHintBundleV1),
            3 => Ok(Self::HarmonyQueryJobV1),
            4 => Ok(Self::OnionEvaluateJobV1),
            5 => Ok(Self::TeeOramQueryV1),
            value => Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "WorkloadId",
                value,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AuthScheme {
    FreeV1 = 1,
    Bolt11DirectReceiptV1 = 2,
    CashuEcashV1 = 3,
    BitcoinPirCashuBatV1 = 4,
    ArcV1Experimental = 5,
}

impl AuthScheme {
    pub(crate) fn decode(value: u8) -> Result<Self, ServiceProtocolError> {
        match value {
            1 => Ok(Self::FreeV1),
            2 => Ok(Self::Bolt11DirectReceiptV1),
            3 => Ok(Self::CashuEcashV1),
            4 => Ok(Self::BitcoinPirCashuBatV1),
            5 => Ok(Self::ArcV1Experimental),
            value => Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "AuthScheme",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DatasetBindingV1 {
    Class { class_id: u16 },
    CatalogEpoch { epoch: u64 },
    ManifestRoot { root: [u8; 32] },
}

impl DatasetBindingV1 {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Class { class_id } => {
                out.push(1);
                out.extend_from_slice(&class_id.to_le_bytes());
            }
            Self::CatalogEpoch { epoch } => {
                out.push(2);
                out.extend_from_slice(&epoch.to_le_bytes());
            }
            Self::ManifestRoot { root } => {
                out.push(3);
                out.extend_from_slice(root);
            }
        }
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, ServiceProtocolError> {
        match decoder.u8("DatasetBindingV1.type")? {
            1 => Ok(Self::Class {
                class_id: decoder.u16("DatasetBindingV1.class_id")?,
            }),
            2 => Ok(Self::CatalogEpoch {
                epoch: decoder.u64("DatasetBindingV1.epoch")?,
            }),
            3 => Ok(Self::ManifestRoot {
                root: decoder.fixed("DatasetBindingV1.root")?,
            }),
            value => Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "DatasetBindingV1",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ServiceScopeV1 {
    pub provider_id: ProviderId,
    pub backend: BackendId,
    pub workload: WorkloadId,
    pub protocol_version: u16,
    pub dataset: DatasetBindingV1,
    pub operation_profile: u16,
    pub entitlement_profile: u16,
}

impl ServiceScopeV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(80);
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.provider_id);
        out.push(self.backend as u8);
        out.push(self.workload as u8);
        out.extend_from_slice(&self.protocol_version.to_le_bytes());
        self.dataset.encode_into(&mut out);
        out.extend_from_slice(&self.operation_profile.to_le_bytes());
        out.extend_from_slice(&self.entitlement_profile.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        let value = Self::decode_from(&mut decoder)?;
        decoder.finish()?;
        Ok(value)
    }

    pub(crate) fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, ServiceProtocolError> {
        let version = decoder.u8("ServiceScopeV1.version")?;
        expect_v1(version, "ServiceScopeV1")?;
        let provider_id = decoder.fixed("ServiceScopeV1.provider_id")?;
        let backend = BackendId::decode(decoder.u8("ServiceScopeV1.backend")?)?;
        let workload = WorkloadId::decode(decoder.u8("ServiceScopeV1.workload")?)?;
        let protocol_version = decoder.u16("ServiceScopeV1.protocol_version")?;
        if protocol_version == 0 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceScopeV1.protocol_version",
                reason: "must be non-zero",
            });
        }
        let dataset = DatasetBindingV1::decode_from(decoder)?;
        let operation_profile = decoder.u16("ServiceScopeV1.operation_profile")?;
        let entitlement_profile = decoder.u16("ServiceScopeV1.entitlement_profile")?;
        let scope = Self {
            provider_id,
            backend,
            workload,
            protocol_version,
            dataset,
            operation_profile,
            entitlement_profile,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ServiceProtocolError> {
        let workload_matches_backend = matches!(
            (self.backend, self.workload),
            (BackendId::DpfPirV1, WorkloadId::DpfEvaluateJobV1)
                | (BackendId::HarmonyPirV2, WorkloadId::HarmonyHintBundleV1)
                | (BackendId::HarmonyPirV2, WorkloadId::HarmonyQueryJobV1)
                | (BackendId::OnionPirV1, WorkloadId::OnionEvaluateJobV1)
                | (BackendId::TeeOramV1, WorkloadId::TeeOramQueryV1)
        );
        if !workload_matches_backend {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceScopeV1.workload",
                reason: "workload does not belong to backend",
            });
        }
        let expected_protocol_version = match self.backend {
            BackendId::DpfPirV1 | BackendId::OnionPirV1 | BackendId::TeeOramV1 => 1,
            BackendId::HarmonyPirV2 => 2,
        };
        if self.protocol_version != expected_protocol_version {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceScopeV1.protocol_version",
                reason: "does not match the selected backend version",
            });
        }
        if self.operation_profile == 0 || self.entitlement_profile == 0 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceScopeV1.profile",
                reason: "operation and entitlement profiles must be non-zero",
            });
        }
        match &self.dataset {
            DatasetBindingV1::Class { class_id } if *class_id == 0 => {
                Err(ServiceProtocolError::InvalidValue {
                    field: "DatasetBindingV1.class_id",
                    reason: "must be non-zero",
                })
            }
            DatasetBindingV1::CatalogEpoch { epoch } if *epoch == 0 => {
                Err(ServiceProtocolError::InvalidValue {
                    field: "DatasetBindingV1.epoch",
                    reason: "must be non-zero",
                })
            }
            DatasetBindingV1::ManifestRoot { root } if root.iter().all(|byte| *byte == 0) => {
                Err(ServiceProtocolError::InvalidValue {
                    field: "DatasetBindingV1.root",
                    reason: "must be non-zero",
                })
            }
            _ => Ok(()),
        }
    }

    pub fn scope_id(&self) -> ScopeId {
        let mut hasher = Sha256::new();
        hasher.update(SCOPE_ID_DOMAIN);
        hasher.update(self.encode());
        hasher.finalize().into()
    }
}

/// Derive a stable provider audience without using URL, IP, or peer identity.
pub fn derive_provider_id(
    operator_ed25519_pubkey: &[u8; 32],
    stable_server_id: &str,
) -> ProviderId {
    let mut hasher = Sha256::new();
    hasher.update(PROVIDER_ID_DOMAIN);
    hasher.update(operator_ed25519_pubkey);
    hasher.update((stable_server_id.len() as u32).to_le_bytes());
    hasher.update(stable_server_id.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }

    fn scope(dataset: DatasetBindingV1) -> ServiceScopeV1 {
        ServiceScopeV1 {
            provider_id: [7; 32],
            backend: BackendId::HarmonyPirV2,
            workload: WorkloadId::HarmonyHintBundleV1,
            protocol_version: 2,
            dataset,
            operation_profile: 11,
            entitlement_profile: 12,
        }
    }

    #[test]
    fn scope_roundtrips_all_dataset_bindings() {
        for dataset in [
            DatasetBindingV1::Class { class_id: 9 },
            DatasetBindingV1::CatalogEpoch { epoch: 42 },
            DatasetBindingV1::ManifestRoot { root: [3; 32] },
        ] {
            let original = scope(dataset);
            assert_eq!(
                ServiceScopeV1::decode(&original.encode()).unwrap(),
                original
            );
        }
    }

    #[test]
    fn scope_hash_changes_for_every_entitlement_axis() {
        let base = scope(DatasetBindingV1::Class { class_id: 1 });
        let mut changed = base.clone();
        changed.workload = WorkloadId::HarmonyQueryJobV1;
        assert_ne!(base.scope_id(), changed.scope_id());
        changed = base.clone();
        changed.entitlement_profile += 1;
        assert_ne!(base.scope_id(), changed.scope_id());
        changed = base.clone();
        changed.provider_id[0] ^= 1;
        assert_ne!(base.scope_id(), changed.scope_id());
    }

    #[test]
    fn scope_decode_rejects_trailing_and_unknown_values() {
        let mut encoded = scope(DatasetBindingV1::Class { class_id: 1 }).encode();
        encoded.push(0);
        assert_eq!(
            ServiceScopeV1::decode(&encoded),
            Err(ServiceProtocolError::TrailingBytes(1))
        );

        let mut encoded = scope(DatasetBindingV1::Class { class_id: 1 }).encode();
        encoded[33] = 99;
        assert!(matches!(
            ServiceScopeV1::decode(&encoded),
            Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "BackendId",
                value: 99
            })
        ));
    }

    #[test]
    fn scope_rejects_backend_workload_and_profile_mismatch() {
        let mut invalid = scope(DatasetBindingV1::Class { class_id: 9 });
        invalid.workload = WorkloadId::DpfEvaluateJobV1;
        assert!(invalid.validate().is_err());

        invalid = scope(DatasetBindingV1::Class { class_id: 9 });
        invalid.protocol_version = 1;
        assert!(invalid.validate().is_err());

        invalid = scope(DatasetBindingV1::Class { class_id: 0 });
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn provider_id_does_not_depend_on_url_or_peer() {
        let a = derive_provider_id(&[1; 32], "stable-server-a");
        let b = derive_provider_id(&[1; 32], "stable-server-a");
        let c = derive_provider_id(&[1; 32], "stable-server-b");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn canonical_provider_and_scope_vectors_are_stable() {
        assert_eq!(
            derive_provider_id(&[1; 32], "server-a").as_slice(),
            decode_hex("26edf1827d387c09e8e088d33532cf8c88cff7607c9817892159362d98c3361e")
        );

        let value = scope(DatasetBindingV1::Class { class_id: 9 });
        let encoded = decode_hex(
            "010707070707070707070707070707070707070707070707070707070707070707020202000109000b000c00",
        );
        assert_eq!(value.encode(), encoded);
        assert_eq!(
            value.scope_id().as_slice(),
            decode_hex("e7234a6b4100c84b3d9d862072caaedd18ef45516bad06db6252f7a2d0352376")
        );
    }
}
