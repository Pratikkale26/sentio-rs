//! Native/pinocchio mutation matrix — the committed form of the harness the
//! rule pack was validated with against Anvil's byte-equal transpiler corpus.
//!
//! Each fixture directory is a minimal transpiled-shaped project. `clean/`
//! carries every check the native layers look for (signer, owner, canonical
//! bump search, has_one compare, discriminator in the deserializer) and must
//! scan EMPTY — it also regression-locks the FP exemptions (canonical
//! `create_program_address` loop, safe deserializer resolution, fresh-rebind
//! post-CPI, and friends). Every mutant strips exactly one protection and
//! must fire exactly its rule:
//!
//!   missing-signer         → SW001  (authority never is_signer-checked)
//!   missing-owner          → SW002  (data trusted, no owner check; bump also
//!                                    stripped — a PDA-checked account cannot
//!                                    be foreign-owned, so owner+bump go
//!                                    together)
//!   missing-discriminator  → SW006  (deserializer body has no [..8] check)
//!   missing-identity       → SW012  (no bump, no has_one — any counter of
//!                                    the right type substitutes)
//!   token-trust            → SW009 + SW010 (balance trusted, no mint/owner
//!                                    field checks, no address binding)

use sentio_core::{ScanOptions, Scanner};
use std::collections::BTreeSet;
use std::path::PathBuf;

fn scan_rule_ids(fixture: &str) -> BTreeSet<String> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/native")
        .join(fixture);
    assert!(dir.is_dir(), "missing fixture dir {dir:?}");
    let options = ScanOptions {
        // fixture paths contain "fixtures"/"tests" components that the
        // default walk skips
        include_tests: true,
        ..ScanOptions::default()
    };
    let result = Scanner::new().scan_path(dir.to_str().unwrap(), &options);
    assert!(
        result.parse_failures.is_empty(),
        "fixture {fixture} failed to parse: {:?}",
        result.parse_failures
    );
    result.findings.iter().map(|f| f.rule_id.clone()).collect()
}

fn expect(fixture: &str, rules: &[&str]) {
    let got = scan_rule_ids(fixture);
    let want: BTreeSet<String> = rules.iter().map(|r| r.to_string()).collect();
    assert_eq!(
        got, want,
        "fixture `{fixture}`: expected exactly {want:?}, got {got:?}"
    );
}

#[test]
fn clean_fixture_scans_empty() {
    expect("clean", &[]);
}

#[test]
fn missing_signer_fires_sw001_only() {
    expect("missing-signer", &["SW001"]);
}

#[test]
fn missing_owner_fires_sw002_only() {
    expect("missing-owner", &["SW002"]);
}

#[test]
fn missing_discriminator_fires_sw006_only() {
    expect("missing-discriminator", &["SW006"]);
}

#[test]
fn missing_identity_fires_sw012_only() {
    expect("missing-identity", &["SW012"]);
}

#[test]
fn token_trust_fires_sw009_and_sw010() {
    expect("token-trust", &["SW009", "SW010"]);
}
