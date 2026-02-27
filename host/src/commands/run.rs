use airbender_host::{Program, Runner, SimulatorRunner};
use anyhow::{bail, Context, Result};
use std::path::Path;
use tracing::info;

use crate::batches::load_batch_words;

use super::EXPECTED_OUTPUT;

pub fn run_batches(program: &Program, batches_dir: &Path, batch_numbers: &[u64]) -> Result<()> {
    let runner = program
        .simulator_runner()
        .with_cycles(usize::MAX)
        .build()
        .context("while attempting to build simulator runner")?;

    for &batch_number in batch_numbers {
        let input_words = load_batch_words(batches_dir, batch_number)
            .with_context(|| format!("while attempting to load batch {batch_number}"))?;
        run_batch(&runner, batch_number, &input_words).with_context(|| {
            format!("while attempting to run batch {batch_number} in simulator")
        })?;
    }

    Ok(())
}

fn run_batch(runner: &SimulatorRunner, batch_number: u64, input_words: &[u32]) -> Result<()> {
    let execution = runner
        .run(input_words)
        .with_context(|| format!("while attempting to execute batch {batch_number}"))?;
    let output = execution.receipt.output[0];

    info!(
        batch_number,
        cycles = execution.cycles_executed,
        reached_end = execution.reached_end,
        output,
        "Finished simulator run"
    );

    if output != EXPECTED_OUTPUT {
        bail!(
            "batch {batch_number} returned unexpected output {output}, expected {EXPECTED_OUTPUT}"
        );
    }

    Ok(())
}
