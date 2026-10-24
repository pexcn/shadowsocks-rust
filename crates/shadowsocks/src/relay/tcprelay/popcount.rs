//! Optional, request-only transform of the initial TCP ciphertext block.
//!
//! Wire layout: original salt, masked lengths, header MAC, shuffled ciphertext and padding.
//! The salt stays visible for printable-salt support; the existing AEAD still authenticates
//! the restored ciphertext. This format requires both peers to opt in.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{context::Context as ServiceContext, crypto::CipherKind};

use super::crypto_io::StreamType;

const MAX_INPUT: usize = 65_535;
const LENGTH_BYTES: usize = 8;
const TAG_BYTES: usize = 16;
const SHUFFLE_CACHE_BYTES: usize = 1024;

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid initial TCP popcount block")
}

fn digest(key: &[u8; 32], domain: &[u8], salt: &[u8], data: &[u8]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(domain);
    hasher.update(salt);
    hasher.update(data);
    hasher.finalize()
}

fn shuffle(data: &mut [u8], key: &[u8; 32], salt: &[u8], inverse: bool) {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(b"shuffle");
    hasher.update(salt);
    hasher.update(&(data.len() as u32).to_be_bytes());
    let mut reader = hasher.finalize_xof();
    let mut cached_block = u64::MAX;
    let mut cache = [0; SHUFFLE_CACHE_BYTES];
    let bits = data.len() * 8;
    let output_len = bits as u64 * 8;
    let mut swap = |index: usize| {
        // Preserve each bit index's XOF position when batching output.
        let byte_position = index as u64 * 8;
        let block = byte_position / SHUFFLE_CACHE_BYTES as u64;
        if block != cached_block {
            let start = block * SHUFFLE_CACHE_BYTES as u64;
            let take = (output_len - start).min(SHUFFLE_CACHE_BYTES as u64) as usize;
            reader.set_position(start);
            reader.fill(&mut cache[..take]);
            cached_block = block;
        }
        let offset = (byte_position % SHUFFLE_CACHE_BYTES as u64) as usize;
        let word = u64::from_le_bytes(cache[offset..offset + 8].try_into().unwrap());
        // A counter-addressed word permits reversing swaps without storing a bit-index vector.
        let other = ((u128::from(word) * (index + 1) as u128) >> 64) as usize;
        let difference = ((data[index / 8] >> (index % 8)) ^ (data[other / 8] >> (other % 8))) & 1;
        data[index / 8] ^= difference << (index % 8);
        data[other / 8] ^= difference << (other % 8);
    };
    if inverse {
        for index in 1..bits {
            swap(index);
        }
    } else {
        for index in (1..bits).rev() {
            swap(index);
        }
    }
}

fn ones(data: &[u8]) -> usize {
    data.iter().map(|byte| byte.count_ones() as usize).sum()
}

fn encode(key: &[u8; 32], salt_len: usize, input: &[u8]) -> io::Result<(Vec<u8>, usize)> {
    if input.len() <= salt_len {
        return Err(invalid());
    }
    let length = (input.len() - salt_len).min(MAX_INPUT);
    let salt = &input[..salt_len];
    let ciphertext = &input[salt_len..salt_len + length];
    let header_len = salt_len + LENGTH_BYTES + TAG_BYTES;
    #[cfg(any(feature = "aead-cipher", feature = "aead-cipher-2022"))]
    let target = {
        use rand::RngExt;
        rand::rng().random_range(300..=330)
    };
    #[cfg(not(any(feature = "aead-cipher", feature = "aead-cipher-2022")))]
    let target = 320;
    let count = ones(ciphertext) + ones(salt);
    // Include the entire header; bound the still-unknown masked lengths and tag conservatively.
    let zeros = (100 * (count + 8 * (LENGTH_BYTES + TAG_BYTES)))
        .saturating_sub(target * (length + header_len))
        .div_ceil(target);
    let high_target = 800 - target;
    let ones_padding = (high_target * (length + header_len))
        .saturating_sub(100 * count)
        .div_ceil(target);
    let (padding, value) = if zeros <= ones_padding {
        (zeros, 0)
    } else {
        (ones_padding, 0xff)
    };
    let body_len = length + padding;
    if body_len > 2 * length + 256 {
        return Err(invalid());
    }
    let mut lengths = [0; LENGTH_BYTES];
    lengths[..4].copy_from_slice(&(length as u32).to_be_bytes());
    lengths[4..].copy_from_slice(&(body_len as u32).to_be_bytes());
    let mask = digest(key, b"length", salt, &[]);
    for (byte, mask) in lengths.iter_mut().zip(mask.as_bytes()) {
        *byte ^= mask;
    }
    let tag = digest(key, b"tag", salt, &lengths);
    let mut wire = Vec::with_capacity(header_len + body_len);
    wire.extend_from_slice(salt);
    wire.extend_from_slice(&lengths);
    wire.extend_from_slice(&tag.as_bytes()[..TAG_BYTES]);
    wire.extend_from_slice(ciphertext);
    wire.resize(header_len + body_len, value);
    shuffle(&mut wire[header_len..], key, salt, false);
    Ok((wire, salt_len + length))
}

fn parse_header(key: &[u8; 32], salt_len: usize, header: &[u8]) -> io::Result<(usize, usize)> {
    let salt = &header[..salt_len];
    let masked = &header[salt_len..salt_len + LENGTH_BYTES];
    let tag = digest(key, b"tag", salt, masked);
    let mut expected = [0; 32];
    let mut received = [0; 32];
    expected[..TAG_BYTES].copy_from_slice(&tag.as_bytes()[..TAG_BYTES]);
    received[..TAG_BYTES].copy_from_slice(&header[salt_len + LENGTH_BYTES..]);
    // Hash equality compares the fixed-size tags in constant time.
    if blake3::Hash::from(expected) != blake3::Hash::from(received) {
        return Err(invalid());
    }
    let mask = digest(key, b"length", salt, &[]);
    let mut lengths = [0; LENGTH_BYTES];
    for ((output, byte), mask) in lengths.iter_mut().zip(masked).zip(mask.as_bytes()) {
        *output = byte ^ mask;
    }
    let length = u32::from_be_bytes(lengths[..4].try_into().unwrap()) as usize;
    let body_len = u32::from_be_bytes(lengths[4..].try_into().unwrap()) as usize;
    if length == 0 || length > MAX_INPUT || body_len < length || body_len > 2 * length + 256 {
        return Err(invalid());
    }
    Ok((length, body_len))
}

enum Phase {
    WriteFirst,
    Writing { position: usize, consumed: usize },
    ReadHeader { position: usize },
    Reading { position: usize, length: usize },
    Decoded { position: usize },
    Done,
    Invalid,
}

pub(crate) struct TcpPopcount {
    key: [u8; 32],
    salt_len: usize,
    header: Vec<u8>,
    buffer: Vec<u8>,
    phase: Phase,
}

impl TcpPopcount {
    pub(crate) fn new(stream_type: StreamType, method: CipherKind, key: &[u8]) -> Self {
        let supported = ServiceContext::supports_tcp_popcount(method);
        #[cfg(any(feature = "aead-cipher", feature = "aead-cipher-2022"))]
        let salt_len = if supported { method.salt_len() } else { 0 };
        #[cfg(not(any(feature = "aead-cipher", feature = "aead-cipher-2022")))]
        let salt_len = 0;
        let mut hasher = blake3::Hasher::new_derive_key("ss-rust initial TCP popcount v1");
        hasher.update(&(key.len() as u32).to_be_bytes());
        hasher.update(key);
        hasher.update(method.to_string().as_bytes());
        Self {
            key: *hasher.finalize().as_bytes(),
            salt_len,
            header: if supported && stream_type == StreamType::Server {
                vec![0; salt_len + LENGTH_BYTES + TAG_BYTES]
            } else {
                Vec::new()
            },
            buffer: Vec::new(),
            phase: match (supported, stream_type) {
                (false, _) => Phase::Invalid,
                (true, StreamType::Client) => Phase::WriteFirst,
                (true, StreamType::Server) => Phase::ReadHeader { position: 0 },
            },
        }
    }

    pub(crate) fn is_done(&self) -> bool {
        matches!(self.phase, Phase::Done)
    }

    fn poll_drain<S: AsyncWrite + Unpin>(&mut self, cx: &mut Context<'_>, stream: &mut S) -> Poll<io::Result<()>> {
        if let Phase::Writing { ref mut position, .. } = self.phase {
            while *position < self.buffer.len() {
                let count = std::task::ready!(Pin::new(&mut *stream).poll_write(cx, &self.buffer[*position..]))?;
                if count == 0 {
                    return Err(io::ErrorKind::WriteZero.into()).into();
                }
                *position += count;
            }
        }
        Ok(()).into()
    }

    fn poll_write<S: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        stream: &mut S,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if matches!(self.phase, Phase::Invalid) {
            return Err(invalid()).into();
        }
        if data.is_empty() {
            return Ok(0).into();
        }
        if matches!(self.phase, Phase::WriteFirst) {
            let (wire, consumed) = encode(&self.key, self.salt_len, data)?;
            self.buffer = wire;
            self.phase = Phase::Writing { position: 0, consumed };
        }
        std::task::ready!(self.poll_drain(cx, stream))?;
        if let Phase::Writing { consumed, .. } = self.phase {
            self.phase = Phase::Done;
            self.buffer.clear();
            return Ok(consumed).into();
        }
        Pin::new(stream).poll_write(cx, data)
    }

    fn poll_read<S: AsyncRead + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        stream: &mut S,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Ok(()).into();
        }
        loop {
            match self.phase {
                Phase::Invalid => return Err(invalid()).into(),
                Phase::ReadHeader { ref mut position } => {
                    let mut buffer = ReadBuf::new(&mut self.header[*position..]);
                    std::task::ready!(Pin::new(&mut *stream).poll_read(cx, &mut buffer))?;
                    let count = buffer.filled().len();
                    if count == 0 {
                        if *position == 0 {
                            self.phase = Phase::Done;
                            return Ok(()).into();
                        }
                        return Err(io::ErrorKind::UnexpectedEof.into()).into();
                    }
                    *position += count;
                    if *position == self.header.len() {
                        let (length, body_len) = parse_header(&self.key, self.salt_len, &self.header)?;
                        self.buffer.resize(body_len, 0);
                        self.phase = Phase::Reading { position: 0, length };
                    }
                }
                Phase::Reading {
                    ref mut position,
                    length,
                } => {
                    let mut buffer = ReadBuf::new(&mut self.buffer[*position..]);
                    std::task::ready!(Pin::new(&mut *stream).poll_read(cx, &mut buffer))?;
                    let count = buffer.filled().len();
                    if count == 0 {
                        return Err(io::ErrorKind::UnexpectedEof.into()).into();
                    }
                    *position += count;
                    if *position == self.buffer.len() {
                        let salt = &self.header[..self.salt_len];
                        shuffle(&mut self.buffer, &self.key, salt, true);
                        self.buffer.truncate(length);
                        self.buffer.resize(length + self.salt_len, 0);
                        self.buffer.copy_within(..length, self.salt_len);
                        self.buffer[..self.salt_len].copy_from_slice(salt);
                        self.phase = Phase::Decoded { position: 0 };
                    }
                }
                Phase::Decoded { ref mut position } => {
                    let count = output.remaining().min(self.buffer.len() - *position);
                    output.put_slice(&self.buffer[*position..*position + count]);
                    *position += count;
                    if *position == self.buffer.len() {
                        self.phase = Phase::Done;
                        self.buffer.clear();
                    }
                    return Ok(()).into();
                }
                _ => return Pin::new(stream).poll_read(cx, output),
            }
        }
    }
}

pub(crate) struct PopcountIo<'a, S> {
    pub(crate) stream: &'a mut S,
    pub(crate) codec: &'a mut TcpPopcount,
}

impl<S: AsyncRead + Unpin> AsyncRead for PopcountIo<'_, S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.codec.poll_read(cx, this.stream, output)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PopcountIo<'_, S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.codec.poll_write(cx, this.stream, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.codec.poll_drain(cx, this.stream))?;
        Pin::new(&mut *this.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.codec.poll_drain(cx, this.stream))?;
        Pin::new(&mut *this.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shuffle_preserves_original_wire_format() {
        // Known outputs from the original 64-byte cache, including the new cache boundary.
        let vectors = [
            (
                32,
                1,
                "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
            ),
            (
                16,
                15,
                "20d0c3e660a8686e8b4c09181ede9ddc90ffa4ab09af22963ccc52b3667d8ddb",
            ),
            (
                16,
                16,
                "fda032a5f7db3113cef64b06f9bdddb28ab574b214550b4942ff4822a98447d1",
            ),
            (
                16,
                17,
                "33fecd736fedffadc41d9813e256f4d4ed2ba7796c58c7b90dc96615280ceaa5",
            ),
            (
                32,
                87_431,
                "649baff2b44a8a332b49ac93ca4dc3be6dbb6f577ba1f125418e1571509c90b4",
            ),
        ];
        for (salt_len, length, expected) in vectors {
            let key = [7; 32];
            let salt = vec![9; salt_len];
            let input: Vec<u8> = (0usize..length)
                .map(|i| (i.wrapping_mul(73) ^ (i >> 3)) as u8)
                .collect();
            let mut data = input.clone();
            shuffle(&mut data, &key, &salt, false);
            assert_eq!(blake3::hash(&data).to_hex().as_str(), expected);
            shuffle(&mut data, &key, &salt, true);
            assert_eq!(data, input);
        }
    }

    #[test]
    fn roundtrip_density_and_authenticated_bounds() {
        let key = [7; 32];
        for salt_len in [16, 32] {
            for length in [1, 2, 17, 64, 511, 1460, 16_383, MAX_INPUT] {
                for pattern in 0..4 {
                    let input: Vec<u8> = (0..salt_len + length)
                        .map(|index| match pattern {
                            0 => 0,
                            1 => 0xff,
                            2 => index as u8,
                            _ => (index.wrapping_mul(73) ^ index.rotate_left(5)) as u8,
                        })
                        .collect();
                    let (wire, consumed) = encode(&key, salt_len, &input).unwrap();
                    assert_eq!(consumed, input.len());
                    let count = 10 * ones(&wire);
                    assert!(count <= 34 * wire.len() || count >= 46 * wire.len());
                    let header_len = salt_len + LENGTH_BYTES + TAG_BYTES;
                    let (decoded_len, body_len) = parse_header(&key, salt_len, &wire[..header_len]).unwrap();
                    assert_eq!(decoded_len, length);
                    assert_eq!(wire.len(), header_len + body_len);
                    let mut decoded = wire[header_len..].to_vec();
                    shuffle(&mut decoded, &key, &wire[..salt_len], true);
                    assert_eq!(&decoded[..length], &input[salt_len..]);
                }
            }
        }

        let (wire, consumed) = encode(&key, 32, &vec![1; MAX_INPUT + 100]).unwrap();
        assert_eq!(consumed, MAX_INPUT + 32);
        let header_len = 32 + LENGTH_BYTES + TAG_BYTES;
        for index in 0..header_len {
            let mut header = wire[..header_len].to_vec();
            header[index] ^= 1;
            assert!(parse_header(&key, 32, &header).is_err());
        }
        assert!(parse_header(&[8; 32], 32, &wire[..header_len]).is_err());

        for (length, body_len) in [(0u32, 1u32), (65_536, 65_536), (10, 9), (10, 277)] {
            let salt = [0; 32];
            let mut lengths = [0; 8];
            lengths[..4].copy_from_slice(&length.to_be_bytes());
            lengths[4..].copy_from_slice(&body_len.to_be_bytes());
            let mask = digest(&key, b"length", &salt, &[]);
            for (byte, mask) in lengths.iter_mut().zip(mask.as_bytes()) {
                *byte ^= mask;
            }
            let tag = digest(&key, b"tag", &salt, &lengths);
            let mut header = salt.to_vec();
            header.extend_from_slice(&lengths);
            header.extend_from_slice(&tag.as_bytes()[..TAG_BYTES]);
            assert!(parse_header(&key, 32, &header).is_err());
        }
    }

    #[cfg(any(feature = "aead-cipher", feature = "aead-cipher-2022"))]
    #[tokio::test]
    async fn fragmented_io_preserves_tail_and_rejects_truncation() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        #[cfg(feature = "aead-cipher")]
        let method = CipherKind::AES_256_GCM;
        #[cfg(not(feature = "aead-cipher"))]
        let method = CipherKind::AEAD2022_BLAKE3_AES_256_GCM;

        struct Fragmented {
            bytes: Vec<u8>,
            position: usize,
            pending: bool,
        }

        impl AsyncWrite for Fragmented {
            fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
                if self.pending {
                    self.pending = false;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                let count = data.len().min(7);
                self.bytes.extend_from_slice(&data[..count]);
                self.pending = true;
                Ok(count).into()
            }

            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Ok(()).into()
            }

            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Ok(()).into()
            }
        }

        impl AsyncRead for Fragmented {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                output: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                if self.pending {
                    self.pending = false;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                if self.position < self.bytes.len() && output.remaining() > 0 {
                    output.put_slice(&self.bytes[self.position..self.position + 1]);
                    self.position += 1;
                    self.pending = true;
                }
                Ok(()).into()
            }
        }

        let key = [3; 32];
        let first = vec![0x69; 120];
        let tail = b"the remaining ciphertext is unchanged";
        let mut sink = Fragmented {
            bytes: Vec::new(),
            position: 0,
            pending: false,
        };
        let mut encoder = TcpPopcount::new(StreamType::Client, method, &key);
        let mut stream = PopcountIo {
            stream: &mut sink,
            codec: &mut encoder,
        };
        stream.write_all(&[]).await.unwrap();
        assert!(stream.stream.bytes.is_empty());
        stream.write_all(&first).await.unwrap();
        let encoded_len = stream.stream.bytes.len();
        stream.write_all(tail).await.unwrap();
        stream.flush().await.unwrap();
        assert_eq!(&sink.bytes[encoded_len..], tail);

        let wire = sink.bytes.clone();
        let mut decoder = TcpPopcount::new(StreamType::Server, method, &key);
        let mut stream = PopcountIo {
            stream: &mut sink,
            codec: &mut decoder,
        };
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, [first.as_slice(), tail].concat());
        assert!(decoder.is_done());

        for length in [1, method.salt_len() + 23, method.salt_len() + 24, encoded_len - 1] {
            let mut source = std::io::Cursor::new(wire[..length].to_vec());
            let mut decoder = TcpPopcount::new(StreamType::Server, method, &key);
            let mut stream = PopcountIo {
                stream: &mut source,
                codec: &mut decoder,
            };
            assert_eq!(
                stream.read_to_end(&mut Vec::new()).await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }
}
