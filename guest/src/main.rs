#![cfg_attr(not(test), no_main)]

mod stream_input;

#[cfg(not(test))]
use zksync_airbender_verifier::types::AirbenderVerifierInput;
#[cfg(not(test))]
use zksync_airbender_verifier::Verify;

#[cfg(not(test))]
#[airbender::main]
fn main() -> [u32; 8] {
    // Stream-decode the input so peak memory is the decoded structure (~1x)
    // rather than the serialized blob plus the decoded structure (~2x). See
    // `stream_input` for details.
    let input: AirbenderVerifierInput =
        stream_input::read_streaming().expect("failed to read AirbenderVerifierInput");
    let result = input.verify().unwrap();
    result.proof_public_input
}
