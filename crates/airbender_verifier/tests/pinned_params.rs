//! Regression: `system_env` parameters that are operator-supplied but bound by
//! no commitment must be pinned to their canonical Era values, so a non-canonical
//! value can't yield a different valid batch.
//!
//! Requires the test batch fetched via Git LFS:
//!   ./scripts/fetch_lfs_batches.sh 84730.bin.gz

use std::path::Path;

use zksync_airbender_verifier::types::AirbenderVerifierInput;
use zksync_airbender_verifier::{Verify, PINNED_PROTOCOL_VERSION};
use zksync_cli_utils::{load_batch, BatchInputFile};
use zksync_types::ProtocolVersionId;

fn load_batch_84730() -> Option<AirbenderVerifierInput> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/era_mainnet_batches/binary/84730.bin.gz");
    if !path.exists()
        || std::fs::metadata(&path)
            .map(|m| m.len() < 1000)
            .unwrap_or(true)
    {
        // This is a security regression, so under CI a missing fixture must fail
        // the job, not silently skip — otherwise a missing-LFS misconfiguration
        // would disable the check while still reporting green. Locally we skip for
        // convenience (the default `cargo test` doesn't fetch LFS).
        assert!(
            std::env::var_os("CI").is_none(),
            "batch 84730 fixture missing under CI — run ./scripts/fetch_lfs_batches.sh before `cargo test`"
        );
        eprintln!("Skipping: batch 84730 fixture missing (run ./scripts/fetch_lfs_batches.sh)");
        return None;
    }
    Some(
        load_batch(&BatchInputFile {
            number: 84730,
            path,
        })
        .expect("load"),
    )
}

/// A real mainnet batch carries the canonical validation gas limit (so the pin
/// doesn't reject honest batches), and overriding it to a non-canonical value
/// is rejected.
#[test]
fn validation_gas_limit_pinned_to_canonical() {
    let Some(v1) = load_batch_84730() else {
        return;
    };

    // Untouched: the real batch carries the canonical (unlimited) value, so it
    // still verifies. The Airbender producer hardcodes u32::MAX (not the
    // state-keeper 300_000 default).
    assert_eq!(
        v1.system_env.default_validation_computational_gas_limit,
        u32::MAX,
        "real mainnet batch should carry the canonical (unlimited) validation gas limit"
    );
    v1.clone().verify().expect("84730 verifies untouched");

    // A non-canonical (smaller) value is rejected.
    let mut tampered = v1;
    tampered
        .system_env
        .default_validation_computational_gas_limit = 300_000;
    let err = match tampered.verify() {
        Ok(_) => panic!("non-canonical validation gas limit must be rejected"),
        Err(e) => e,
    };
    assert!(
        err.to_string()
            .contains("default_validation_computational_gas_limit"),
        "expected a validation-gas-limit rejection, got: {err}"
    );
}

/// The protocol-minor labels the input carries are operator-supplied and bound
/// by no commitment. A real batch carries the version this build models, and
/// substituting any other minor — older *or* newer — is rejected before the VM
/// runs, so the label can never select which semantics the batch is proved
/// under.
#[test]
fn protocol_version_pinned_to_modelled_semantics() {
    let Some(v1) = load_batch_84730() else {
        return;
    };

    assert_eq!(
        v1.system_env.version, PINNED_PROTOCOL_VERSION,
        "real mainnet batch should carry the protocol version this build models"
    );
    assert_eq!(
        v1.vm_run_data.protocol_version, PINNED_PROTOCOL_VERSION,
        "the redundant copy in vm_run_data should agree"
    );

    // Version29 is the previous minor (a different `FastVmVersion`); Version32 is
    // the speculative next one, which maps to the *same* `FastVmVersion` as the
    // pinned version — so only the version gate distinguishes it.
    for version in [ProtocolVersionId::Version29, ProtocolVersionId::Version32] {
        let mut tampered = v1.clone();
        tampered.system_env.version = version;
        tampered.vm_run_data.protocol_version = version;
        let err = match tampered.verify() {
            Ok(_) => panic!("substituted protocol version {version:?} must be rejected"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("unsupported protocol version"),
            "expected a protocol-version rejection for {version:?}, got: {err}"
        );
    }
}
