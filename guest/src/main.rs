#![no_main]

use airbender::guest::read;
use zksync_tee_verifier::types::{CommitmentInput, TeeVerifierInput};
use zksync_tee_verifier::verify_and_commit;

#[airbender::main]
fn main() -> [u32; 8] {
    let input: TeeVerifierInput = read().expect("failed to read TeeVerifierInput");
    let TeeVerifierInput::V1(input) = input else {
        panic!("expected TeeVerifierInput::V1")
    };
    let commitment_input: CommitmentInput = read().expect("failed to read CommitmentInput");

    let result = verify_and_commit(input, commitment_input).unwrap();
    result.proof_public_input
}
