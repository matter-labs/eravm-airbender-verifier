#![no_main]

use airbender::guest::read;
use zksync_airbender_verifier::types::AirbenderVerifierInput;
use zksync_airbender_verifier::Verify;

#[airbender::main]
fn main() -> [u32; 8] {
    let input: AirbenderVerifierInput = read().expect("failed to read AirbenderVerifierInput");
    let result = input.verify().unwrap();
    result.proof_public_input
}
