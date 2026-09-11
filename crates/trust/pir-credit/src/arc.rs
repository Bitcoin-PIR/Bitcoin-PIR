//! ARC credentials as credits (docs/CREDITS.md "ARC parameters"): the
//! epoch arithmetic, the request and presentation contexts both sides
//! derive from an epoch, the `REQ_CREDIT_PRESENT` kind-2 payload codec, and
//! the `/v2/credentials` JSON types. The cryptography itself lives in the
//! `arc` crate (Bitcoin-PIR/arc); this module only fixes the bytes the
//! issuer and the clients must agree on.
//!
//! One credential is one pack: `presentation_limit` presentations, one
//! credit each, so a presentation never reveals which pack it came from.
//! The presentation context is fixed per epoch, so the issuer keeps one
//! global tag set per epoch and a tag reused anywhere is a double spend.

use serde::{Deserialize, Serialize};

/// Presentations one credential allows (one credit each).
pub const ARC_PRESENTATION_LIMIT: u32 = 100;
/// Issuer key lifetime: credentials are issued under the current epoch.
pub const ARC_EPOCH_SECS: u64 = 90 * 24 * 60 * 60;
/// How long after an epoch ends its credentials are still accepted.
pub const ARC_GRACE_SECS: u64 = 30 * 24 * 60 * 60;
/// Most presentations one kind-2 payload may carry (a HarmonyPIR hint set).
pub const MAX_ARC_PRESENTATIONS_PER_PAYLOAD: usize = 150;
/// Largest serialized presentation the codec accepts.
pub const MAX_ARC_PRESENTATION_LEN: usize = 4096;

const REQUEST_CONTEXT_PREFIX: &[u8] = b"BitcoinPIR/credits/v1/request/";
const PRESENTATION_CONTEXT_PREFIX: &[u8] = b"BitcoinPIR/credits/v1/presentation/";

/// The epoch `now` falls in.
pub fn epoch_at(now: u64, epoch_secs: u64) -> u32 {
    if epoch_secs == 0 {
        return 0;
    }
    u32::try_from(now / epoch_secs).unwrap_or(u32::MAX)
}

/// Whether presentations under `epoch` are still accepted at `now`: the
/// epoch is the current one, or it ended less than `grace_secs` ago.
pub fn epoch_accepted(epoch: u32, now: u64, epoch_secs: u64, grace_secs: u64) -> bool {
    if epoch_secs == 0 {
        return false;
    }
    let current = epoch_at(now, epoch_secs);
    if epoch == current {
        return true;
    }
    if epoch.checked_add(1) != Some(current) {
        return false;
    }
    let ended_at = u64::from(current).saturating_mul(epoch_secs);
    now < ended_at.saturating_add(grace_secs)
}

/// Unix second after which `epoch`'s credentials are refused.
pub fn epoch_valid_until(epoch: u32, epoch_secs: u64, grace_secs: u64) -> u64 {
    (u64::from(epoch) + 1)
        .saturating_mul(epoch_secs)
        .saturating_add(grace_secs)
}

/// ARC `requestContext` (the public attribute `m2`) of an epoch.
pub fn request_context(epoch: u32) -> Vec<u8> {
    let mut out = REQUEST_CONTEXT_PREFIX.to_vec();
    out.extend_from_slice(epoch.to_string().as_bytes());
    out
}

/// ARC `presentationContext` of an epoch: fixed, so tags are globally
/// unique per epoch.
pub fn presentation_context(epoch: u32) -> Vec<u8> {
    let mut out = PRESENTATION_CONTEXT_PREFIX.to_vec();
    out.extend_from_slice(epoch.to_string().as_bytes());
    out
}

/// `REQ_CREDIT_PRESENT` kind-2 payload: `[epoch u32 LE][count u16 LE]`
/// then `count` × `[len u16 LE][presentation bytes]`.
pub fn encode_presentations(
    epoch: u32,
    presentations: &[Vec<u8>],
) -> Result<Vec<u8>, &'static str> {
    if presentations.is_empty() {
        return Err("no presentations");
    }
    if presentations.len() > MAX_ARC_PRESENTATIONS_PER_PAYLOAD {
        return Err("too many presentations in one payload");
    }
    let mut out = Vec::with_capacity(6 + presentations.iter().map(|p| 2 + p.len()).sum::<usize>());
    out.extend_from_slice(&epoch.to_le_bytes());
    out.extend_from_slice(&(presentations.len() as u16).to_le_bytes());
    for presentation in presentations {
        if presentation.is_empty() || presentation.len() > MAX_ARC_PRESENTATION_LEN {
            return Err("presentation length out of range");
        }
        out.extend_from_slice(&(presentation.len() as u16).to_le_bytes());
        out.extend_from_slice(presentation);
    }
    Ok(out)
}

/// Inverse of [`encode_presentations`]; exact length, bounded count.
pub fn decode_presentations(payload: &[u8]) -> Result<(u32, Vec<&[u8]>), &'static str> {
    if payload.len() < 6 {
        return Err("payload too short");
    }
    let epoch = u32::from_le_bytes(payload[0..4].try_into().expect("four bytes"));
    let count = usize::from(u16::from_le_bytes(
        payload[4..6].try_into().expect("two bytes"),
    ));
    if count == 0 || count > MAX_ARC_PRESENTATIONS_PER_PAYLOAD {
        return Err("presentation count out of range");
    }
    let mut presentations = Vec::with_capacity(count);
    let mut rest = &payload[6..];
    for _ in 0..count {
        if rest.len() < 2 {
            return Err("presentation length missing");
        }
        let len = usize::from(u16::from_le_bytes(
            rest[0..2].try_into().expect("two bytes"),
        ));
        if len == 0 || len > MAX_ARC_PRESENTATION_LEN {
            return Err("presentation length out of range");
        }
        rest = &rest[2..];
        if rest.len() < len {
            return Err("presentation truncated");
        }
        presentations.push(&rest[..len]);
        rest = &rest[len..];
    }
    if !rest.is_empty() {
        return Err("trailing bytes after the last presentation");
    }
    Ok((epoch, presentations))
}

/// `POST /v2/credentials` body: pay `sat` of ecash for one credential of
/// `credits` presentations, blinded request attached.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRequestV2 {
    /// A listed offer (`credits` must equal the issuer's presentation limit).
    pub credits: u64,
    pub sat: u64,
    /// `cashuB…` token worth exactly `sat`.
    pub token: String,
    /// `arc::CredentialRequest::to_bytes`, lowercase hex.
    pub request_hex: String,
}

/// `POST /v2/credentials` success body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialResponseV2 {
    /// `arc::CredentialResponse::to_bytes`, lowercase hex.
    pub response_hex: String,
    pub epoch: u32,
    pub presentation_limit: u32,
    /// `arc::ServerPublicKey::to_bytes` (99 bytes) of `epoch`, lowercase hex.
    pub issuer_public_key_hex: String,
    /// Unix second after which the credential is refused.
    pub valid_until: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epochs_roll_every_ninety_days_with_thirty_days_of_grace() {
        assert_eq!(epoch_at(0, ARC_EPOCH_SECS), 0);
        assert_eq!(epoch_at(ARC_EPOCH_SECS - 1, ARC_EPOCH_SECS), 0);
        assert_eq!(epoch_at(ARC_EPOCH_SECS, ARC_EPOCH_SECS), 1);
        assert_eq!(epoch_at(1_800_000_000, ARC_EPOCH_SECS), 231);
        let start_of_232 = 232 * ARC_EPOCH_SECS;
        assert!(epoch_accepted(
            232,
            start_of_232,
            ARC_EPOCH_SECS,
            ARC_GRACE_SECS
        ));
        assert!(epoch_accepted(
            231,
            start_of_232,
            ARC_EPOCH_SECS,
            ARC_GRACE_SECS
        ));
        assert!(epoch_accepted(
            231,
            start_of_232 + ARC_GRACE_SECS - 1,
            ARC_EPOCH_SECS,
            ARC_GRACE_SECS
        ));
        assert!(!epoch_accepted(
            231,
            start_of_232 + ARC_GRACE_SECS,
            ARC_EPOCH_SECS,
            ARC_GRACE_SECS
        ));
        assert!(!epoch_accepted(
            230,
            start_of_232,
            ARC_EPOCH_SECS,
            ARC_GRACE_SECS
        ));
        assert!(
            !epoch_accepted(233, start_of_232, ARC_EPOCH_SECS, ARC_GRACE_SECS),
            "the future is not an epoch"
        );
        assert_eq!(
            epoch_valid_until(231, ARC_EPOCH_SECS, ARC_GRACE_SECS),
            start_of_232 + ARC_GRACE_SECS
        );
        assert_eq!(epoch_at(5, 0), 0);
        assert!(!epoch_accepted(0, 5, 0, 0));
    }

    #[test]
    fn contexts_are_domain_separated_and_epoch_bound() {
        assert_eq!(
            request_context(231),
            b"BitcoinPIR/credits/v1/request/231".to_vec()
        );
        assert_eq!(
            presentation_context(231),
            b"BitcoinPIR/credits/v1/presentation/231".to_vec()
        );
        assert_ne!(request_context(231), request_context(232));
        assert_ne!(request_context(231), presentation_context(231));
    }

    #[test]
    fn payload_codec_round_trips_and_rejects_malformed_input() {
        let a = vec![1u8; 300];
        let b = vec![2u8; 301];
        let payload = encode_presentations(231, &[a.clone(), b.clone()]).unwrap();
        assert_eq!(&payload[..6], &[231, 0, 0, 0, 2, 0]);
        let (epoch, presentations) = decode_presentations(&payload).unwrap();
        assert_eq!(epoch, 231);
        assert_eq!(presentations, vec![a.as_slice(), b.as_slice()]);
        assert!(encode_presentations(1, &[]).is_err());
        assert!(encode_presentations(1, &[Vec::new()]).is_err());
        assert!(encode_presentations(1, &[vec![0; MAX_ARC_PRESENTATION_LEN + 1]]).is_err());
        assert!(
            encode_presentations(1, &vec![vec![1u8]; MAX_ARC_PRESENTATIONS_PER_PAYLOAD + 1])
                .is_err()
        );
        assert!(decode_presentations(&payload[..5]).is_err());
        assert!(decode_presentations(&payload[..payload.len() - 1]).is_err());
        let mut trailing = payload.clone();
        trailing.push(0);
        assert!(decode_presentations(&trailing).is_err());
        let mut zero_count = payload.clone();
        zero_count[4] = 0;
        assert!(decode_presentations(&zero_count).is_err());
        let mut zero_len = payload.clone();
        zero_len[6] = 0;
        zero_len[7] = 0;
        assert!(decode_presentations(&zero_len).is_err());
    }

    #[test]
    fn credential_bodies_round_trip() {
        let request = CredentialRequestV2 {
            credits: 100,
            sat: 1_000,
            token: "cashuB".into(),
            request_hex: "00".repeat(226),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(
            serde_json::from_str::<CredentialRequestV2>(&json).unwrap(),
            request
        );
        let response = CredentialResponseV2 {
            response_hex: "00".repeat(454),
            epoch: 231,
            presentation_limit: ARC_PRESENTATION_LIMIT,
            issuer_public_key_hex: "00".repeat(99),
            valid_until: 1,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(
            serde_json::from_str::<CredentialResponseV2>(&json).unwrap(),
            response
        );
    }
}
