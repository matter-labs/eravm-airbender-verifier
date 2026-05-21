use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::Deserialize;
use zksync_cli_utils::{load_batch, resolve_batch_inputs, BatchInputFile};
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

#[derive(Debug, Deserialize)]
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
    let rows = manifest
        .findings
        .iter()
        .map(|finding| evaluate_finding(finding, &cli.batches_dir, options))
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

fn evaluate_finding(finding: &Finding, batches_dir: &Path, options: CompareOptions) -> Row {
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
            match run_batch_reproducer(finding, batches_dir, options) {
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
        match compare_batch(&batch_input, options) {
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

fn compare_batch(batch_input: &BatchInputFile, options: CompareOptions) -> Result<Option<String>> {
    let input = load_batch(batch_input)
        .with_context(|| {
            format!(
                "while attempting to load batch {} from {}",
                batch_input.number,
                batch_input.path.display()
            )
        })?
        .into_v1()
        .with_context(|| format!("batch {} has no V1 payload", batch_input.number))?;

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
