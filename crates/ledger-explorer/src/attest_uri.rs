//! Attestation URI seam. Undecided domain stays under `.invalid`; emit and
//! verify must share the configuration.

/// Placeholder base under `.invalid`: never routes, stays visible.
pub const DEFAULT_ATTESTATION_BASE: &str = "https://ledger.invalid";

const BASE_ENV: &str = "LEDGER_ATTESTATION_BASE";

/// Configured base: env override or the `.invalid` placeholder.
pub fn attestation_base() -> String {
    // Host-side config; never on the simulation path.
    // ledger-lint:allow:env::var (host-side attestation domain config; deployment seam reads the override at emit/verify time)
    attestation_base_from(std::env::var(BASE_ENV).ok().as_deref())
}

/// Pure resolver: blank selects the placeholder; trailing slash trimmed.
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
