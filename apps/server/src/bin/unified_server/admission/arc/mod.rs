//! ARC admission facade (D2).
//!
//! Single construction boundary for the provider-local ARC verifier, so the
//! legacy flag wiring in `unified_server/` collapses to one call site. The
//! verifier itself (`pir_runtime_core::arc_verifier`) stays put; the single
//! designated issuer lives outside the node — this facade only checks that
//! presented tokens were issued under an accepted key.

use std::sync::Mutex;

use pir_runtime_core::arc_verifier::ArcVerifier;
use zeroize::Zeroize;

use crate::{read_exact_secret_v1, CliArgs};

/// Provider-local ARC admission state: an optional verifier plus whether
/// presentation is required for query opcodes.
pub(crate) struct ArcAdmissionV1 {
    verifier: Option<Mutex<ArcVerifier>>,
    require: bool,
}

impl ArcAdmissionV1 {
    /// Build from the legacy `--require-arc` / `--arc-key` flags. Log lines
    /// and failure behavior match the historical inline wiring verbatim.
    pub(crate) fn from_cli(args: &CliArgs) -> Result<Self, String> {
        if !args.require_arc {
            println!("  ARC: disabled (use --require-arc to enable)");
            return Ok(Self {
                verifier: None,
                require: false,
            });
        }
        let verifier = match args.arc_key_path.as_ref() {
            Some(path) => {
                let mut secret = read_exact_secret_v1::<128>(path, "ARC key").map_err(|error| {
                    format!("failed to load ARC key from {}: {error}", path.display())
                })?;
                let verifier = ArcVerifier::from_secret_key_bytes(&secret).map_err(|error| {
                    format!("failed to load ARC key from {}: {error}", path.display())
                })?;
                secret.zeroize();
                println!(
                    "  ARC: enabled — verification required (shared key loaded from {})",
                    path.display()
                );
                verifier
            }
            None => {
                let verifier = ArcVerifier::generate();
                eprintln!(
                    "  ARC: WARNING — --require-arc set without --arc-key; generated a random \
                     key. No externally-issued credential will verify. Pass --arc-key <arc_key.bin> \
                     to share the issuer's key."
                );
                verifier
            }
        };
        Ok(Self {
            verifier: Some(Mutex::new(verifier)),
            require: true,
        })
    }

    pub(crate) fn into_parts(self) -> (Option<Mutex<ArcVerifier>>, bool) {
        (self.verifier, self.require)
    }
}

#[cfg(test)]
mod tests {
    use crate::admission::arc::ArcAdmissionV1;
    use crate::parse_args_from;

    #[test]
    fn disabled_when_not_required() {
        let args = parse_args_from(vec!["unified_server".to_owned()]);
        let admission = ArcAdmissionV1::from_cli(&args).expect("from_cli");
        let (verifier, require) = admission.into_parts();
        assert!(!require);
        assert!(verifier.is_none());
    }
}
