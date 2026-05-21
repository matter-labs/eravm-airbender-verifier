use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::Deserialize;
use zksync_airbender_verifier::types::V1AirbenderVerifierInput;
use zksync_cli_utils::{load_batch, resolve_batch_inputs, BatchInputFile};
use zksync_types::H256;
use zksync_vm_compare::{CompareOptions, ComparisonOutcome};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Validate divergence finding reproducibility with vm_compare"
)]
struct Cli {
    #[arg(long, default_value = "../vm-compare-findings.json")]
    manifest: PathBuf,

    #[arg(long)]
    ledger: Option<PathBuf>,

    #[arg(long, default_value = "testdata/vm_compare_findings/binary")]
    batches_dir: PathBuf,

    /// Trusted batch whose base system contract bytecodes every reproducer must match.
    ///
    /// This is required if the manifest contains any `batch_reproducer` entries.
    /// It prevents accepting repro batches that patch base system contract code.
    #[arg(long)]
    system_contracts_baseline: Option<PathBuf>,

    #[arg(long, default_value_t = CompareOptions::default().max_capture_bytes)]
    max_capture_bytes: usize,

    #[arg(long)]
    no_fail_fast: bool,

    #[arg(long)]
    markdown: bool,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    findings: Vec<Finding>,
}

#[derive(Debug, Deserialize)]
struct Finding {
    id: String,
    #[allow(dead_code)]
    title: Option<String>,
    vm_compare: VmCompareFinding,
}

#[derive(Debug, Deserialize)]
struct VmCompareFinding {
    status: VmCompareStatus,
    #[serde(default)]
    batch_files: Vec<PathBuf>,
    #[serde(default)]
    expected_substrings: Vec<String>,
    #[serde(default)]
    reason: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VmCompareStatus {
    BatchReproducer,
    NeedsBatchReproducer,
    NotRepresentable,
}

#[derive(Debug)]
struct Row {
    id: String,
    status: String,
    batch_files: String,
    detail: String,
    failed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContractFingerprint {
    hash: H256,
    code: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SystemContractsFingerprint {
    bootloader: ContractFingerprint,
    default_aa: ContractFingerprint,
    evm_emulator: Option<ContractFingerprint>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let manifest = load_manifest(&cli.manifest)?;
    validate_unique_ids(&manifest)?;

    if let Some(ledger) = &cli.ledger {
        check_ledger_coverage(ledger, &manifest)?;
    }

    let options = CompareOptions {
        max_capture_bytes: cli.max_capture_bytes,
        fail_fast: !cli.no_fail_fast,
    };
    let system_contracts_baseline = load_required_system_contracts_baseline(
        &manifest,
        &cli.batches_dir,
        &cli.system_contracts_baseline,
    )?;
    let rows = manifest
        .findings
        .iter()
        .map(|finding| {
            evaluate_finding(
                finding,
                &cli.batches_dir,
                options,
                system_contracts_baseline.as_ref(),
            )
        })
        .collect::<Vec<_>>();

    if cli.markdown {
        print_markdown(&rows);
    } else {
        print_text(&rows);
    }

    if rows.iter().any(|row| row.failed) {
        bail!("one or more batch-backed vm_compare validations failed");
    }
    Ok(())
}

fn load_required_system_contracts_baseline(
    manifest: &Manifest,
    batches_dir: &Path,
    baseline_path: &Option<PathBuf>,
) -> Result<Option<SystemContractsFingerprint>> {
    let has_batch_reproducer = manifest
        .findings
        .iter()
        .any(|finding| matches!(finding.vm_compare.status, VmCompareStatus::BatchReproducer));
    if !has_batch_reproducer {
        return Ok(None);
    }

    let baseline_path = baseline_path.as_ref().context(
        "manifest contains batch_reproducer entries; pass --system-contracts-baseline \
         <trusted-batch.bin[.gz]> so repro batches cannot patch base system contracts",
    )?;
    let baseline_inputs = resolve_batch_inputs(
        batches_dir,
        Some(std::slice::from_ref(baseline_path)),
        false,
    )
    .context("while resolving system contracts baseline batch")?;
    let baseline_input = baseline_inputs
        .first()
        .context("system contracts baseline resolution returned no batch")?;
    let input = load_v1_batch(baseline_input)?;
    Ok(Some(system_contracts_fingerprint(&input)))
}

fn load_manifest(path: &Path) -> Result<Manifest> {
    let bytes = fs::read(path).with_context(|| format!("while reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("while parsing {}", path.display()))
}

fn validate_unique_ids(manifest: &Manifest) -> Result<()> {
    let mut ids = BTreeSet::new();
    for finding in &manifest.findings {
        if !ids.insert(&finding.id) {
            bail!("duplicate finding id {}", finding.id);
        }
    }
    Ok(())
}

fn check_ledger_coverage(ledger: &Path, manifest: &Manifest) -> Result<()> {
    let ledger_text = fs::read_to_string(ledger)
        .with_context(|| format!("while reading {}", ledger.display()))?;
    let ledger_ids = ledger_text
        .lines()
        .filter_map(|line| {
            let heading = line.strip_prefix("## D-")?;
            let suffix = heading.split(':').next()?;
            Some(format!("D-{suffix}"))
        })
        .collect::<BTreeSet<_>>();
    let manifest_ids = manifest
        .findings
        .iter()
        .map(|finding| finding.id.clone())
        .collect::<BTreeSet<_>>();

    let missing = ledger_ids
        .difference(&manifest_ids)
        .cloned()
        .collect::<Vec<_>>();
    let extra = manifest_ids
        .difference(&ledger_ids)
        .cloned()
        .collect::<Vec<_>>();
    if missing.is_empty() && extra.is_empty() {
        return Ok(());
    }

    if !missing.is_empty() {
        eprintln!("missing from manifest: {}", missing.join(", "));
    }
    if !extra.is_empty() {
        eprintln!("not present in ledger: {}", extra.join(", "));
    }
    bail!("manifest does not cover ledger findings");
}

fn evaluate_finding(
    finding: &Finding,
    batches_dir: &Path,
    options: CompareOptions,
    system_contracts_baseline: Option<&SystemContractsFingerprint>,
) -> Row {
    match finding.vm_compare.status {
        VmCompareStatus::NeedsBatchReproducer => Row {
            id: finding.id.clone(),
            status: "No - pending full-batch repro".to_owned(),
            batch_files: batch_files_display(&finding.vm_compare.batch_files),
            detail: finding.vm_compare.reason.clone(),
            failed: false,
        },
        VmCompareStatus::NotRepresentable => Row {
            id: finding.id.clone(),
            status: "No - not representable by current vm_compare".to_owned(),
            batch_files: batch_files_display(&finding.vm_compare.batch_files),
            detail: finding.vm_compare.reason.clone(),
            failed: false,
        },
        VmCompareStatus::BatchReproducer => {
            match run_batch_reproducer(finding, batches_dir, options, system_contracts_baseline) {
                Ok(detail) => Row {
                    id: finding.id.clone(),
                    status: "Yes - vm_compare reproduced".to_owned(),
                    batch_files: batch_files_display(&finding.vm_compare.batch_files),
                    detail,
                    failed: false,
                },
                Err(error) => Row {
                    id: finding.id.clone(),
                    status: "Error".to_owned(),
                    batch_files: batch_files_display(&finding.vm_compare.batch_files),
                    detail: error.to_string(),
                    failed: true,
                },
            }
        }
    }
}

fn run_batch_reproducer(
    finding: &Finding,
    batches_dir: &Path,
    options: CompareOptions,
    system_contracts_baseline: Option<&SystemContractsFingerprint>,
) -> Result<String> {
    if finding.vm_compare.batch_files.is_empty() {
        bail!("status is batch_reproducer but no batch_files were provided");
    }

    let batch_inputs = resolve_batch_inputs(
        batches_dir,
        Some(finding.vm_compare.batch_files.as_slice()),
        false,
    )
    .context("while resolving batch reproducer inputs")?;

    let mut reproduced = Vec::new();
    let mut matched = Vec::new();
    for batch_input in batch_inputs {
        match compare_batch(&batch_input, options, system_contracts_baseline) {
            Ok(Some(report_text)) => {
                ensure_expected_substrings(finding, &report_text)?;
                reproduced.push(format!("{} ({report_text})", batch_input.path.display()));
            }
            Ok(None) => matched.push(batch_input.path.display().to_string()),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "while running vm_compare for {} on {}",
                        finding.id,
                        batch_input.path.display()
                    )
                });
            }
        }
    }

    if reproduced.is_empty() {
        bail!("vm_compare matched on {}", matched.join(", "));
    }
    Ok(format!("vm_compare diverged on {}", reproduced.join("; ")))
}

fn compare_batch(
    batch_input: &BatchInputFile,
    options: CompareOptions,
    system_contracts_baseline: Option<&SystemContractsFingerprint>,
) -> Result<Option<String>> {
    let input = load_v1_batch(batch_input)?;
    if let Some(baseline) = system_contracts_baseline {
        ensure_system_contracts_match(batch_input, &input, baseline)?;
    }

    let report = zksync_vm_compare::compare(input, options).with_context(|| {
        format!(
            "while attempting to compare batch {} from {}",
            batch_input.number,
            batch_input.path.display()
        )
    })?;
    match &report.outcome {
        ComparisonOutcome::Match => Ok(None),
        ComparisonOutcome::Diverged(divergences) => {
            let reasons = divergences
                .iter()
                .map(|divergence| divergence.reason.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            Ok(Some(format!("{report}; reasons: {reasons}")))
        }
    }
}

fn load_v1_batch(batch_input: &BatchInputFile) -> Result<V1AirbenderVerifierInput> {
    load_batch(batch_input)
        .with_context(|| {
            format!(
                "while attempting to load batch {} from {}",
                batch_input.number,
                batch_input.path.display()
            )
        })?
        .into_v1()
        .with_context(|| format!("batch {} has no V1 payload", batch_input.number))
}

fn system_contracts_fingerprint(input: &V1AirbenderVerifierInput) -> SystemContractsFingerprint {
    let base = &input.system_env.base_system_smart_contracts;
    SystemContractsFingerprint {
        bootloader: ContractFingerprint {
            hash: base.bootloader.hash,
            code: base.bootloader.code.clone(),
        },
        default_aa: ContractFingerprint {
            hash: base.default_aa.hash,
            code: base.default_aa.code.clone(),
        },
        evm_emulator: base
            .evm_emulator
            .as_ref()
            .map(|contract| ContractFingerprint {
                hash: contract.hash,
                code: contract.code.clone(),
            }),
    }
}

fn ensure_system_contracts_match(
    batch_input: &BatchInputFile,
    input: &V1AirbenderVerifierInput,
    baseline: &SystemContractsFingerprint,
) -> Result<()> {
    let actual = system_contracts_fingerprint(input);
    ensure_contract_matches(
        batch_input,
        "bootloader",
        &actual.bootloader,
        &baseline.bootloader,
    )?;
    ensure_contract_matches(
        batch_input,
        "default_aa",
        &actual.default_aa,
        &baseline.default_aa,
    )?;
    match (&actual.evm_emulator, &baseline.evm_emulator) {
        (Some(actual), Some(expected)) => {
            ensure_contract_matches(batch_input, "evm_emulator", actual, expected)?;
        }
        (None, None) => {}
        (Some(_), None) => {
            bail!(
                "{} has an EVM emulator base system contract but baseline does not",
                batch_input.path.display()
            );
        }
        (None, Some(_)) => {
            bail!(
                "{} is missing the EVM emulator base system contract required by baseline",
                batch_input.path.display()
            );
        }
    }
    Ok(())
}

fn ensure_contract_matches(
    batch_input: &BatchInputFile,
    name: &str,
    actual: &ContractFingerprint,
    expected: &ContractFingerprint,
) -> Result<()> {
    if actual.hash != expected.hash {
        bail!(
            "{} {name} hash mismatch: actual {:?}, expected {:?}",
            batch_input.path.display(),
            actual.hash,
            expected.hash
        );
    }
    if actual.code != expected.code {
        bail!(
            "{} {name} bytecode mismatch: actual {} bytes, expected {} bytes",
            batch_input.path.display(),
            actual.code.len(),
            expected.code.len()
        );
    }
    Ok(())
}

fn ensure_expected_substrings(finding: &Finding, report_text: &str) -> Result<()> {
    let missing = finding
        .vm_compare
        .expected_substrings
        .iter()
        .filter(|substring| !report_text.contains(substring.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if missing.is_empty() {
        return Ok(());
    }
    bail!(
        "vm_compare diverged for {}, but expected substrings were missing: {}",
        finding.id,
        missing.join(", ")
    );
}

fn batch_files_display(batch_files: &[PathBuf]) -> String {
    if batch_files.is_empty() {
        return "-".to_owned();
    }
    batch_files
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn print_markdown(rows: &[Row]) {
    println!("| Finding | vm_compare status | Batch files | Reason |");
    println!("|---|---|---|---|");
    for row in rows {
        println!(
            "| {} | {} | {} | {} |",
            escape_markdown_cell(&row.id),
            escape_markdown_cell(&row.status),
            escape_markdown_cell(&row.batch_files),
            escape_markdown_cell(&row.detail)
        );
    }
}

fn print_text(rows: &[Row]) {
    for row in rows {
        println!(
            "{}: {}; batches={}; {}",
            row.id, row.status, row.batch_files, row.detail
        );
    }
}

fn escape_markdown_cell(value: &str) -> String {
    value.replace('|', "\\|")
}
