//! Attestation URI seam: one source for the predicate/build-type base.
//!
//! The public domain is not chosen yet; the control plane will own that
//! decision. Until then every attestation URI derives from
//! [`attestation_base`], which reads `LEDGER_ATTESTATION_BASE` and falls
//! back to the reserved `.invalid` placeholder. Emission and verification
//! must run with the same configuration, because the base is part of the
//! emitted statement bytes.

/// Placeholder base under the RFC 2606 `.invalid` zone: it can never route,
/// which keeps the undecided-domain status visible in every emitted artifact.
pub const DEFAULT_ATTESTATION_BASE: &str = "https://ledger.invalid";

const BASE_ENV: &str = "LEDGER_ATTESTATION_BASE";

/// Configured attestation base: `LEDGER_ATTESTATION_BASE` when set, else the
/// `.invalid` placeholder.
pub fn attestation_base() -> String {
    // Host-side attestation domain config; never on the simulation path.
    // ledger-lint:allow:env::var (host-side attestation domain config; deployment seam reads the override at emit/verify time)
    attestation_base_from(std::env::var(BASE_ENV).ok().as_deref())
}

/// Pure resolver behind [`attestation_base`]: `None`, empty, or blank
/// configuration selects the placeholder; a trailing slash is trimmed so path
/// joins stay single-slash regardless of caller input.
pub fn attestation_base_from(configured: Option<&str>) -> String {
    let raw = configured
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or(DEFAULT_ATTESTATION_BASE);
    raw.trim_end_matches('/').to_string()
}

/// Predicate type for campaign certificates (in-toto Statement).
pub fn predicate_type_campaign_v1() -> String {
    predicate_type_campaign_v1_from(attestation_base().as_str())
}

/// Pure variant of [`predicate_type_campaign_v1`] over an explicit base.
pub fn predicate_type_campaign_v1_from(base: &str) -> String {
    format!(
        "{}/attestations/campaign/v1",
        attestation_base_from(Some(base))
    )
}

/// Build type recorded by campaign certificates (SLSA provenance shape).
pub fn build_type_campaign_v1() -> String {
    build_type_campaign_v1_from(attestation_base().as_str())
}

/// Pure variant of [`build_type_campaign_v1`] over an explicit base.
pub fn build_type_campaign_v1_from(base: &str) -> String {
    format!(
        "{}/build-types/campaign/v1",
        attestation_base_from(Some(base))
    )
}

/// Predicate type for worker task attestations.
pub fn predicate_type_task_v1() -> String {
    format!("{}/attestations/task/v1", attestation_base())
}

/// Tool identity URI used in SARIF output.
pub fn tool_information_uri() -> String {
    attestation_base()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_resolution_is_pure_and_trims() {
        assert_eq!(attestation_base_from(None), DEFAULT_ATTESTATION_BASE);
        assert_eq!(
            attestation_base_from(Some("https://attest.example.org/")),
            "https://attest.example.org"
        );
        assert_eq!(
            attestation_base_from(Some("https://attest.example.org")),
            "https://attest.example.org"
        );
        // Empty or blank configuration counts as unset.
        assert_eq!(attestation_base_from(Some("")), DEFAULT_ATTESTATION_BASE);
        assert_eq!(attestation_base_from(Some("  ")), DEFAULT_ATTESTATION_BASE);
        assert_eq!(
            predicate_type_campaign_v1_from("https://attest.example.org"),
            "https://attest.example.org/attestations/campaign/v1"
        );
        assert_eq!(
            build_type_campaign_v1_from("https://attest.example.org"),
            "https://attest.example.org/build-types/campaign/v1"
        );
    }
}
