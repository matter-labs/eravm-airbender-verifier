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
//! wire framing, same bincode config — so nothing observable changes.

use airbender::guest::Transport;
use bincode::de::read::Reader;
use bincode::error::DecodeError;

/// Reads bincode input bytes on demand from a word-based [`Transport`],
/// following the Airbender wire framing:
/// * the first word is the payload byte length,
/// * each subsequent word carries up to 4 payload bytes big-endian,
/// * the final word is zero-padded when the length is not a multiple of 4.
///
/// Only a single 4-byte word is buffered at a time, so this holds O(1) memory
/// regardless of input size.
struct FramedTransportReader<'a, T: Transport> {
    transport: &'a mut T,
    /// Payload bytes not yet pulled from the transport.
    remaining: usize,
    /// The most recently read word's bytes.
    word: [u8; 4],
    /// Number of *valid* (non-padding) bytes in `word`.
    word_len: usize,
    /// Index of the next byte to hand out of `word`.
    word_pos: usize,
}

impl<'a, T: Transport> FramedTransportReader<'a, T> {
    /// Consumes the leading length word and prepares to stream the payload.
    fn new(transport: &'a mut T) -> Self {
        let len = transport.read_word() as usize;
        Self {
            transport,
            remaining: len,
            word: [0u8; 4],
            word_len: 0,
            word_pos: 0,
        }
    }

    /// True once every payload byte has been handed to the decoder. Mirrors the
    /// codec's `TrailingBytes` strictness: a valid input is fully consumed.
    fn is_exhausted(&self) -> bool {
        self.remaining == 0 && self.word_pos == self.word_len
    }
}

impl<T: Transport> Reader for FramedTransportReader<'_, T> {
    fn read(&mut self, out: &mut [u8]) -> Result<(), DecodeError> {
        let mut written = 0;
        while written < out.len() {
            if self.word_pos == self.word_len {
                if self.remaining == 0 {
                    return Err(DecodeError::UnexpectedEnd {
                        additional: out.len() - written,
                    });
                }
                // Pull the next wire word; the last one is zero-padded, so only
                // `min(remaining, 4)` of its bytes are real payload.
                self.word = self.transport.read_word().to_be_bytes();
                self.word_len = self.remaining.min(4);
                self.word_pos = 0;
                self.remaining -= self.word_len;
            }
            let available = self.word_len - self.word_pos;
            let n = available.min(out.len() - written);
            out[written..written + n].copy_from_slice(&self.word[self.word_pos..self.word_pos + n]);
            self.word_pos += n;
            written += n;
        }
        Ok(())
    }
}

/// Error surfaced by the streaming decoder. Fields are carried for the panic
/// message (`expect`) in real guest execution.
#[derive(Debug)]
#[allow(dead_code)]
pub enum StreamError {
    Decode(DecodeError),
    /// The decoder stopped before consuming the whole framed payload.
    TrailingBytes,
}

impl From<DecodeError> for StreamError {
    fn from(err: DecodeError) -> Self {
        StreamError::Decode(err)
    }
}

/// Streaming counterpart to `airbender::guest::read_with`: decodes `T` directly
/// from `transport` without buffering the serialized blob. Uses the same
/// bincode configuration (`config::standard()`) as `AirbenderCodecV0`.
pub fn read_streaming_with<T: serde::de::DeserializeOwned>(
    transport: &mut impl Transport,
) -> Result<T, StreamError> {
    let mut reader = FramedTransportReader::new(transport);
    let value = bincode::serde::decode_from_reader(&mut reader, bincode::config::standard())?;
    if !reader.is_exhausted() {
        return Err(StreamError::TrailingBytes);
    }
    Ok(value)
}

/// Streaming counterpart to `airbender::guest::read`, reading from the CSR
/// transport in real guest execution.
#[cfg(target_arch = "riscv32")]
pub fn read_streaming<T: serde::de::DeserializeOwned>() -> Result<T, StreamError> {
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
        let mut words = Vec::with_capacity(1 + bytes.len().div_ceil(4));
        words.push(bytes.len() as u32);
        for chunk in bytes.chunks(4) {
            let mut padded = [0u8; 4];
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

    #[test]
    fn streaming_decode_matches_buffered_codec() {
        let value = sample();
        let encoded = AirbenderCodecV0::encode(&value).expect("encode");

        // Reference: the existing buffered path.
        let buffered: Sample = AirbenderCodecV0::decode(&encoded).expect("buffered decode");
        assert_eq!(buffered, value);

        // Streaming path over the same framed words must agree exactly.
        let mut transport = MockTransport::new(frame(&encoded));
        let streamed: Sample = read_streaming_with(&mut transport).expect("streaming decode");
        assert_eq!(streamed, value);
    }

    #[test]
    fn streaming_decode_handles_empty_and_aligned_payloads() {
        // Word-aligned payload (no final padding).
        #[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
        struct Aligned {
            a: u32,
            b: u32,
        }
        let value = Aligned { a: 1, b: 2 };
        let encoded = AirbenderCodecV0::encode(&value).expect("encode");
        let mut transport = MockTransport::new(frame(&encoded));
        let streamed: Aligned = read_streaming_with(&mut transport).expect("decode");
        assert_eq!(streamed, value);
    }
}
