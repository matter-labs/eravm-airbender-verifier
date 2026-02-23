#![no_main]

use airbender::guest::read;
use zksync_tee_verifier::types::TeeVerifierInput;
use zksync_tee_verifier::Verify;

#[airbender::main]
fn main() -> u32 {
    let input: TeeVerifierInput = read().expect("failed to read TeeVerifierInput");
    let TeeVerifierInput::V1(input) = input else {
        panic!("expected TeeVerifierInput::V1")
    };

    input.verify().unwrap();
    1
}
