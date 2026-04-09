#![no_main]

use airbender::guest::read;
use zksync_tee_verifier::types::TeeVerifierInput;
use zksync_tee_verifier::verify_and_commit;

#[airbender::main]
fn main() -> [u32; 8] {
    let input: TeeVerifierInput = read().expect("failed to read TeeVerifierInput");
    let TeeVerifierInput::V2(input) = input else {
        panic!("expected TeeVerifierInput::V2")
    };

    let result = verify_and_commit(input).unwrap();
    result.proof_public_input
}
