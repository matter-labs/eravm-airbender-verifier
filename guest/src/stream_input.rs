//! Streaming decode of the verifier input.
//!
//! The default `airbender::guest::read()` path first materializes the *entire*
//! framed input into a `Vec<u8>` (`read_framed_bytes_with`) and only then
//! bincode-deserializes it into the target structure — so at the moment of
//! decoding, both the full serialized blob and the fully-decoded structure are
//! resident. Peak memory is therefore ~2x the input size.
//!
//! For an adversarial input (e.g. a transaction that decommits hundreds of MB
//! of unique bytecode) that doubling alone can exhaust the ~1 GB guest heap
//! during deserialization, before any execution runs.
//!
//! This module decodes in a single streaming pass: bytes are pulled from the
//! word transport on demand and fed straight into bincode, so the serialized
//! blob is never materialized. Peak memory drops to ~1x (just the decoded
//! structure). The decoded value is bit-identical to the buffered path — same
//! wire framing (mirrors `airbender_core::wire`), same bincode config, and the
//! same `CodecError` accept/reject set as `AirbenderCodecV0` — so nothing
//! observable changes.

use airbender::codec::CodecError;
use airbender::guest::Transport;
use bincode::de::read::Reader;
use bincode::error::DecodeError;

/// Payload bytes carried per transport word.
const WORD_BYTES: usize = 4;

/// Reads bincode input bytes on demand from a word-based [`Transport`],
/// following the Airbender wire framing:
/// * the first word is the payload byte length,
/// * each subsequent word carries up to `WORD_BYTES` payload bytes big-endian,
/// * the final word is zero-padded when the length is not a multiple of 4.
///
/// Only a single word is buffered at a time, so this holds O(1) memory
/// regardless of input size.
struct FramedTransportReader<'a, T: Transport> {
    transport: &'a mut T,
    /// Total framed payload length, kept for the trailing-bytes report.
    len: usize,
    /// Payload bytes not yet handed to the decoder. Exhausted iff this is zero.
    remaining: usize,
    /// The most recently read word's bytes.
    word: [u8; WORD_BYTES],
    /// Index of the next byte to hand out of `word`; `WORD_BYTES` means empty.
    word_pos: usize,
}

impl<'a, T: Transport> FramedTransportReader<'a, T> {
    /// Consumes the leading length word and prepares to stream the payload.
    fn new(transport: &'a mut T) -> Self {
        let len = transport.read_word() as usize;
        Self {
            transport,
            len,
            remaining: len,
            word: [0u8; WORD_BYTES],
            // Empty to start, so the first byte requested pulls a word.
            word_pos: WORD_BYTES,
        }
    }
}

impl<T: Transport> Reader for FramedTransportReader<'_, T> {
    fn read(&mut self, out: &mut [u8]) -> Result<(), DecodeError> {
        let mut written = 0;
        while written < out.len() {
            // Reject insufficient input before touching any state, so a failed
            // read leaves the reader untouched.
            if self.remaining == 0 {
                return Err(DecodeError::UnexpectedEnd {
                    additional: out.len() - written,
                });
            }
            if self.word_pos == WORD_BYTES {
                self.word = self.transport.read_word().to_be_bytes();
                self.word_pos = 0;
            }
            // Bytes left in the current word, capped by unconsumed payload so
            // the final word's zero padding is never handed to the decoder.
            let available = (WORD_BYTES - self.word_pos).min(self.remaining);
            let n = available.min(out.len() - written);
            out[written..written + n].copy_from_slice(&self.word[self.word_pos..self.word_pos + n]);
            self.word_pos += n;
            self.remaining -= n;
            written += n;
        }
        Ok(())
    }
}

/// Streaming counterpart to `airbender::guest::read_with`: decodes `T` directly
/// from `transport` without buffering the serialized blob. Uses the same
/// bincode configuration (`config::standard()`) and returns the same
/// [`CodecError`] set as `AirbenderCodecV0`.
pub fn read_streaming_with<T: serde::de::DeserializeOwned>(
    transport: &mut impl Transport,
) -> Result<T, CodecError> {
    let mut reader = FramedTransportReader::new(transport);
    let value = bincode::serde::decode_from_reader(&mut reader, bincode::config::standard())
        .map_err(CodecError::Decode)?;
    // Mirror the codec's strictness: a valid input is consumed in full.
    if reader.remaining != 0 {
        return Err(CodecError::TrailingBytes {
            expected: reader.len,
            read: reader.len - reader.remaining,
        });
    }
    Ok(value)
}

/// Streaming counterpart to `airbender::guest::read`, reading from the CSR
/// transport in real guest execution.
///
/// Like upstream `read`, this compiles on every target: `CsrTransport`
/// implements `Transport` on the host too (as a panic stub), so a host-side
/// `cargo check` builds `main` without pulling in riscv32 intrinsics. It only
/// ever runs for real on riscv32. Gated out of the test profile (where `main`
/// is also absent) since the tests drive `read_streaming_with` directly.
#[cfg(not(test))]
pub fn read_streaming<T: serde::de::DeserializeOwned>() -> Result<T, CodecError> {
    let mut transport = airbender::guest::CsrTransport;
    read_streaming_with(&mut transport)
}

#[cfg(test)]
mod tests {
    use super::*;
    use airbender::codec::{AirbenderCodec, AirbenderCodecV0};
    use airbender::guest::MockTransport;

    /// Frame bytes into transport words exactly like the Airbender wire format:
    /// length word, then big-endian payload words (last zero-padded).
    fn frame(bytes: &[u8]) -> Vec<u32> {
        let mut words = Vec::with_capacity(1 + bytes.len().div_ceil(WORD_BYTES));
        words.push(bytes.len() as u32);
        for chunk in bytes.chunks(WORD_BYTES) {
            let mut padded = [0u8; WORD_BYTES];
            padded[..chunk.len()].copy_from_slice(chunk);
            words.push(u32::from_be_bytes(padded));
        }
        words
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
    struct Sample {
        counter: u32,
        bytes: Vec<u8>,
        nested: Vec<(u64, String)>,
    }

    fn sample() -> Sample {
        Sample {
            counter: 7,
            // A non-word-aligned length exercises the padded final word.
            bytes: vec![10u8, 20, 30, 40, 50],
            nested: vec![(1, "a".into()), (u64::MAX, "airbender".into())],
        }
    }

    /// Encodes `value` with the buffered codec and asserts the streaming path
    /// decodes it identically over the framed words.
    fn assert_roundtrip<T>(value: T)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + core::fmt::Debug + PartialEq,
    {
        let encoded = AirbenderCodecV0::encode(&value).expect("encode");
        // Reference: the existing buffered path must agree first.
        let buffered: T = AirbenderCodecV0::decode(&encoded).expect("buffered decode");
        assert_eq!(buffered, value);
        // Streaming path over the same framed words must agree exactly.
        let mut transport = MockTransport::new(frame(&encoded));
        let streamed: T = read_streaming_with(&mut transport).expect("streaming decode");
        assert_eq!(streamed, value);
    }

    #[test]
    fn streaming_decode_matches_buffered_codec_across_lengths() {
        assert_roundtrip(()); // zero-length payload: frame is just the length word `0`
        assert_roundtrip([0xAAu8; 8]); // word-aligned payload, no final padding
        assert_roundtrip([1u8, 2, 3, 4, 5]); // non-aligned: padded final word
        assert_roundtrip(sample()); // mixed types with a non-aligned length
        assert_roundtrip((
            // Large multiword payload — the shape of the real input: many words
            // and a big Vec<u8> that bincode reads in one chunk. 10_000 is not a
            // multiple of 4, so the final word is padded.
            0xdead_beef_0bad_f00du64,
            (0..10_000u32)
                .map(|i| (i * 31 + 7) as u8)
                .collect::<Vec<u8>>(),
            (0..257u32).collect::<Vec<u32>>(),
        ));
    }

    #[test]
    fn streaming_decode_rejects_trailing_bytes_like_the_codec() {
        // The buffered codec errors (`TrailingBytes`) when the frame carries
        // more bytes than the value consumes; the streaming path must match,
        // and must report that *specific* error rather than any failure.
        let value = sample();
        let mut encoded = AirbenderCodecV0::encode(&value).expect("encode");
        encoded.extend_from_slice(&[0u8; 5]); // 5 trailing bytes

        assert!(
            matches!(
                AirbenderCodecV0::decode::<Sample>(&encoded),
                Err(CodecError::TrailingBytes { .. })
            ),
            "buffered codec must reject trailing bytes"
        );
        let mut transport = MockTransport::new(frame(&encoded));
        let err = read_streaming_with::<Sample>(&mut transport)
            .expect_err("streaming decode must reject trailing bytes too");
        assert!(
            matches!(err, CodecError::TrailingBytes { .. }),
            "expected CodecError::TrailingBytes, got {err:?}"
        );
    }
}
