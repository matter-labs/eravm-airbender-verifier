#![no_main]

use airbender::guest::read;
use zksync_tee_verifier::types::TeeVerifierInput;
use zksync_tee_verifier::Verify;

#[airbender::main]
fn main() -> [u32; 8] {
    let input: TeeVerifierInput = read().expect("failed to read TeeVerifierInput");
    let result = input.verify().unwrap();
    result.proof_public_input
}
