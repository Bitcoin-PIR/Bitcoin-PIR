//! Access policy (docs/CREDITS.md "Access policy"): per backend, whether a
//! server charges for its metered frames, serves them free, or serves them
//! free on a best-effort lane that paid frames always overtake.
//!
//! Every server sets its own policy and publishes it in `GET_INFO_JSON`
//! (`"credits": {"access": {...}}`); clients read it per server, so an
//! operator can run a fully free server, a fully paid one, or anything in
//! between, and one client works against all of them.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::gas::MeteredOp;

/// Prefix of the `RESP_ERROR` message a server sends when a frame could not
/// get onto a best-effort free lane (all free slots taken, queue full, or the
/// free budget spent). Distinct from "insufficient gas": paying would get the
/// frame served now, waiting may get it served free later.
pub const FREE_LANE_BUSY_PREFIX: &str = "free capacity busy";

/// Whether a server error message is a best-effort lane refusal.
pub fn is_free_lane_busy(message: &str) -> bool {
    message.starts_with(FREE_LANE_BUSY_PREFIX)
}

/// The backend families a server meters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    Dpf,
    Harmony,
    Onion,
    Oram,
}

impl Backend {
    pub const ALL: [Backend; 4] = [
        Backend::Dpf,
        Backend::Harmony,
        Backend::Onion,
        Backend::Oram,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Backend::Dpf => "dpf",
            Backend::Harmony => "harmony",
            Backend::Onion => "onion",
            Backend::Oram => "oram",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|b| b.name() == name)
    }
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl MeteredOp {
    /// The backend family this op belongs to. Bucket-Merkle tree tops are
    /// fetched by both DPF and HarmonyPIR clients and are listed under DPF
    /// here; [`AccessPolicy::for_op`] prices them by the more open of the two.
    pub const fn backend(self) -> Backend {
        match self {
            MeteredOp::DpfIndexRound
            | MeteredOp::DpfChunkRound
            | MeteredOp::DpfSiblingPass { .. }
            | MeteredOp::TreeTops => Backend::Dpf,
            MeteredOp::OnionRegisterKeys
            | MeteredOp::OnionIndexQuery
            | MeteredOp::OnionChunkQuery
            | MeteredOp::OnionSiblingQuery { .. }
            | MeteredOp::OnionTreeTops => Backend::Onion,
            MeteredOp::HarmonyHintSet { .. }
            | MeteredOp::HarmonyPoolEntry
            | MeteredOp::HarmonyContinuation
            | MeteredOp::HarmonyQuery { .. } => Backend::Harmony,
            MeteredOp::OramLookup => Backend::Oram,
        }
    }
}

/// How a server treats one backend's metered frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum Access {
    /// Never charged.
    Free,
    /// Charged to the connection's credits; refused ("insufficient gas")
    /// when they do not cover the frame.
    Paid,
    /// Charged when the connection's credits cover the frame, and then
    /// served first. Otherwise served free on a best-effort lane: at most
    /// `free_concurrency` free frames of this backend run at once, at low
    /// priority; the next ones wait in a FIFO queue for a bounded time, and
    /// with `free_gas_per_hour` set the lane also stops once that much free
    /// work was done in the last hour. Beyond that the frame is refused as
    /// busy ([`FREE_LANE_BUSY_PREFIX`]).
    BestEffort {
        free_concurrency: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        free_gas_per_hour: Option<u64>,
    },
}

impl Access {
    /// Openness order: free, then best-effort, then paid.
    const fn openness(self) -> u8 {
        match self {
            Access::Free => 2,
            Access::BestEffort { .. } => 1,
            Access::Paid => 0,
        }
    }

    pub const fn is_free(self) -> bool {
        matches!(self, Access::Free)
    }

    /// Parse the command-line form: `free`, `paid`, or
    /// `best-effort[:CONCURRENCY[:GAS_PER_HOUR]]` (concurrency defaults to 1).
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut parts = text.split(':');
        let mode = parts.next().unwrap_or_default();
        let rest: Vec<&str> = parts.collect();
        match mode {
            "free" | "paid" if !rest.is_empty() => {
                Err(format!("access mode `{mode}` takes no parameters: {text}"))
            }
            "free" => Ok(Access::Free),
            "paid" => Ok(Access::Paid),
            "best-effort" => {
                if rest.len() > 2 {
                    return Err(format!(
                        "best-effort takes at most CONCURRENCY:GAS_PER_HOUR: {text}"
                    ));
                }
                let free_concurrency = match rest.first() {
                    None => 1,
                    Some(value) => value
                        .parse::<u32>()
                        .ok()
                        .filter(|c| *c >= 1)
                        .ok_or_else(|| {
                            format!("best-effort concurrency must be an integer ≥ 1: {text}")
                        })?,
                };
                let free_gas_per_hour = match rest.get(1) {
                    None => None,
                    Some(value) => Some(
                        value
                            .parse::<u64>()
                            .ok()
                            .filter(|g| *g >= 1)
                            .ok_or_else(|| {
                                format!("best-effort gas per hour must be an integer ≥ 1: {text}")
                            })?,
                    ),
                };
                Ok(Access::BestEffort {
                    free_concurrency,
                    free_gas_per_hour,
                })
            }
            _ => Err(format!(
                "unknown access mode `{mode}` (expected free, paid, or best-effort[:CONCURRENCY[:GAS_PER_HOUR]]): {text}"
            )),
        }
    }
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Access::Free => f.write_str("free"),
            Access::Paid => f.write_str("paid"),
            Access::BestEffort {
                free_concurrency,
                free_gas_per_hour: None,
            } => write!(f, "best-effort:{free_concurrency}"),
            Access::BestEffort {
                free_concurrency,
                free_gas_per_hour: Some(gas),
            } => write!(f, "best-effort:{free_concurrency}:{gas}"),
        }
    }
}

/// One server's policy: an [`Access`] per backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessPolicy {
    dpf: Access,
    harmony: Access,
    onion: Access,
    oram: Access,
}

impl AccessPolicy {
    pub const fn uniform(access: Access) -> Self {
        Self {
            dpf: access,
            harmony: access,
            onion: access,
            oram: access,
        }
    }

    pub const fn get(&self, backend: Backend) -> Access {
        match backend {
            Backend::Dpf => self.dpf,
            Backend::Harmony => self.harmony,
            Backend::Onion => self.onion,
            Backend::Oram => self.oram,
        }
    }

    pub fn set(&mut self, backend: Backend, access: Access) {
        match backend {
            Backend::Dpf => self.dpf = access,
            Backend::Harmony => self.harmony = access,
            Backend::Onion => self.onion = access,
            Backend::Oram => self.oram = access,
        }
    }

    /// The backend whose setting prices `op`, and that setting. Bucket-Merkle
    /// tree tops serve DPF and HarmonyPIR alike, so they follow the more open
    /// of the two (DPF on a tie): a server that lets either backend run free
    /// does not charge the verification data it needs.
    pub fn for_op(&self, op: MeteredOp) -> (Backend, Access) {
        if matches!(op, MeteredOp::TreeTops) && self.harmony.openness() > self.dpf.openness() {
            return (Backend::Harmony, self.harmony);
        }
        let backend = op.backend();
        (backend, self.get(backend))
    }

    /// Whether some backend always requires payment — the legacy
    /// `credits.required` flag older clients read.
    pub fn any_paid(&self) -> bool {
        Backend::ALL
            .into_iter()
            .any(|b| matches!(self.get(b), Access::Paid))
    }

    /// Whether every backend is free.
    pub fn all_free(&self) -> bool {
        Backend::ALL.into_iter().all(|b| self.get(b).is_free())
    }

    /// The published form (`"credits": {"access": ...}`).
    pub fn published(&self) -> PublishedAccess {
        PublishedAccess {
            dpf: Some(self.dpf),
            harmony: Some(self.harmony),
            onion: Some(self.onion),
            oram: Some(self.oram),
        }
    }
}

impl fmt::Display for AccessPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = Backend::ALL
            .into_iter()
            .map(|b| format!("{b}={}", self.get(b)))
            .collect();
        f.write_str(&parts.join(" "))
    }
}

/// The access policy as a server publishes it. A client reading a server
/// that predates the field, or leaves a backend out, falls back to the
/// legacy `credits.required` flag ([`PublishedAccess::resolve`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedAccess {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpf: Option<Access>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harmony: Option<Access>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub onion: Option<Access>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oram: Option<Access>,
}

impl PublishedAccess {
    /// The policy a client should assume: published entries as given, the
    /// rest paid when the server says credits are required, free otherwise.
    pub fn resolve(published: Option<&PublishedAccess>, legacy_required: bool) -> AccessPolicy {
        let fallback = if legacy_required {
            Access::Paid
        } else {
            Access::Free
        };
        let published = published.copied().unwrap_or_default();
        AccessPolicy {
            dpf: published.dpf.unwrap_or(fallback),
            harmony: published.harmony.unwrap_or(fallback),
            onion: published.onion.unwrap_or(fallback),
            oram: published.oram.unwrap_or(fallback),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gas::TableKind;

    const BE2: Access = Access::BestEffort {
        free_concurrency: 2,
        free_gas_per_hour: None,
    };

    #[test]
    fn modes_parse_and_print_round_trip() {
        for text in [
            "free",
            "paid",
            "best-effort:1",
            "best-effort:2",
            "best-effort:4:3600000",
        ] {
            assert_eq!(Access::parse(text).unwrap().to_string(), text);
        }
        assert_eq!(
            Access::parse("best-effort").unwrap(),
            Access::BestEffort {
                free_concurrency: 1,
                free_gas_per_hour: None
            }
        );
        for bad in [
            "",
            "cheap",
            "free:1",
            "paid:2",
            "best-effort:0",
            "best-effort:x",
            "best-effort:2:0",
            "best-effort:2:3:4",
        ] {
            assert!(Access::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn every_op_has_a_backend_and_tree_tops_follow_the_more_open_bucket_backend() {
        assert_eq!(MeteredOp::DpfIndexRound.backend(), Backend::Dpf);
        assert_eq!(
            MeteredOp::DpfSiblingPass {
                table: TableKind::Chunk,
                level: 1
            }
            .backend(),
            Backend::Dpf
        );
        assert_eq!(MeteredOp::OnionTreeTops.backend(), Backend::Onion);
        assert_eq!(MeteredOp::HarmonyPoolEntry.backend(), Backend::Harmony);
        assert_eq!(MeteredOp::OramLookup.backend(), Backend::Oram);

        let mut policy = AccessPolicy::uniform(Access::Paid);
        assert_eq!(
            policy.for_op(MeteredOp::TreeTops),
            (Backend::Dpf, Access::Paid)
        );
        policy.set(Backend::Harmony, BE2);
        assert_eq!(policy.for_op(MeteredOp::TreeTops), (Backend::Harmony, BE2));
        policy.set(Backend::Dpf, BE2);
        assert_eq!(
            policy.for_op(MeteredOp::TreeTops),
            (Backend::Dpf, BE2),
            "tie: DPF"
        );
        policy.set(Backend::Dpf, Access::Free);
        assert_eq!(
            policy.for_op(MeteredOp::TreeTops),
            (Backend::Dpf, Access::Free)
        );
        // Onion tree tops are not bucket-Merkle: they stay with Onion.
        assert_eq!(
            policy.for_op(MeteredOp::OnionTreeTops),
            (Backend::Onion, Access::Paid)
        );
    }

    #[test]
    fn production_policy_publishes_and_resolves() {
        let mut policy = AccessPolicy::uniform(Access::Paid);
        policy.set(Backend::Dpf, BE2);
        policy.set(Backend::Oram, BE2);
        assert!(policy.any_paid());
        assert!(!policy.all_free());
        assert_eq!(
            policy.to_string(),
            "dpf=best-effort:2 harmony=paid onion=paid oram=best-effort:2"
        );
        let json = serde_json::to_string(&policy.published()).unwrap();
        assert_eq!(
            json,
            r#"{"dpf":{"mode":"best-effort","free_concurrency":2},"harmony":{"mode":"paid"},"onion":{"mode":"paid"},"oram":{"mode":"best-effort","free_concurrency":2}}"#
        );
        let parsed: PublishedAccess = serde_json::from_str(&json).unwrap();
        assert_eq!(PublishedAccess::resolve(Some(&parsed), true), policy);
    }

    #[test]
    fn a_server_without_the_field_falls_back_to_the_legacy_flag() {
        assert_eq!(
            PublishedAccess::resolve(None, true),
            AccessPolicy::uniform(Access::Paid)
        );
        assert_eq!(
            PublishedAccess::resolve(None, false),
            AccessPolicy::uniform(Access::Free)
        );
        let partial: PublishedAccess = serde_json::from_str(
            r#"{"oram":{"mode":"best-effort","free_concurrency":3,"free_gas_per_hour":7200}}"#,
        )
        .unwrap();
        let resolved = PublishedAccess::resolve(Some(&partial), true);
        assert_eq!(resolved.get(Backend::Dpf), Access::Paid);
        assert_eq!(
            resolved.get(Backend::Oram),
            Access::BestEffort {
                free_concurrency: 3,
                free_gas_per_hour: Some(7200)
            }
        );
        assert!(AccessPolicy::uniform(Access::Free).all_free());
        assert!(!AccessPolicy::uniform(BE2).any_paid());
    }

    #[test]
    fn busy_refusals_are_recognised_by_prefix() {
        assert!(is_free_lane_busy(
            "free capacity busy: dpf serves 2 free frame(s) at a time"
        ));
        assert!(!is_free_lane_busy("insufficient gas: this frame needs 25"));
    }
}
