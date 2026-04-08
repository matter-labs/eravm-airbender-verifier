#![no_main]

use airbender::guest::read;
use zksync_tee_verifier::types::AirbenderVerifierInput;
use zksync_tee_verifier::Verify;

#[airbender::main]
fn main() -> [u32; 8] {
    let input: AirbenderVerifierInput = read().expect("failed to read AirbenderVerifierInput");
    let AirbenderVerifierInput::V2(input) = input else {
        panic!("expected AirbenderVerifierInput::V2")
    };

    let result = input.verify().unwrap();
    result.proof_public_input
}
