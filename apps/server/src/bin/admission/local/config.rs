//! TOML surface for local admission. The file is operator-local; it is not
//! signed, versioned, or distributed.

use std::path::Path;

use serde::Deserialize;

/// Local admission configuration (all fields optional; open defaults).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalAdmissionConfigV1 {
    /// Free queries are served without credentials. Default: true.
    #[serde(default = "default_free_open")]
    pub(crate) free_open: bool,
    /// Endpoint of the single designated issuer for paid ARC tokens. The
    /// server only announces this URL to clients; it does not verify tokens
    /// online (ARC verification is provider-local against the issuer key).
    #[serde(default)]
    pub(crate) arc_issuer_url: Option<String>,
}

fn default_free_open() -> bool {
    true
}

impl Default for LocalAdmissionConfigV1 {
    fn default() -> Self {
        Self {
            free_open: default_free_open(),
            arc_issuer_url: None,
        }
    }
}

impl LocalAdmissionConfigV1 {
    pub(crate) fn load(path: Option<&Path>) -> Result<Self, String> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("local admission config {}: {e}", path.display()))?;
        let config: Self = toml::from_str(&raw)
            .map_err(|e| format!("local admission config {} is invalid TOML: {e}", path.display()))?;
        if let Some(url) = config.arc_issuer_url.as_deref() {
            if !(url.starts_with("https://") || url.starts_with("wss://")) {
                return Err(format!(
                    "local admission config {}: arc_issuer_url must start with https:// or wss://",
                    path.display()
                ));
            }
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::LocalAdmissionConfigV1;

    #[test]
    fn empty_file_uses_open_defaults() {
        let config: LocalAdmissionConfigV1 = toml::from_str("").expect("empty toml parses");
        assert!(config.free_open);
        assert!(config.arc_issuer_url.is_none());
    }

    #[test]
    fn parses_full_document() {
        let config: LocalAdmissionConfigV1 = toml::from_str(
            "free_open = false\narc_issuer_url = \"https://issuer.example.com\"\n",
        )
        .expect("full toml parses");
        assert!(!config.free_open);
        assert_eq!(config.arc_issuer_url.as_deref(), Some("https://issuer.example.com"));
    }

    #[test]
    fn rejects_unknown_fields() {
        let error = toml::from_str::<LocalAdmissionConfigV1>("surprise = true\n").unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn rejects_non_tls_issuer_url() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("admission.toml");
        std::fs::write(&file, "arc_issuer_url = \"http://issuer.example.com\"\n").unwrap();
        let error = LocalAdmissionConfigV1::load(Some(&file)).unwrap_err();
        assert!(error.contains("https://"), "unexpected error: {error}");
    }

    #[test]
    fn missing_file_is_an_error_not_a_silent_default() {
        let path = std::path::Path::new("/nonexistent/local-admission.toml");
        let error = LocalAdmissionConfigV1::load(Some(path)).unwrap_err();
        assert!(error.contains("local admission config"), "unexpected error: {error}");
    }
}
