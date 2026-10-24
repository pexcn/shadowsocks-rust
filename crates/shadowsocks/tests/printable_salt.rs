#![cfg(any(feature = "aead-cipher", feature = "aead-cipher-2022"))]

use std::{future::poll_fn, io::Cursor, pin::Pin};

use shadowsocks::{
    config::{ReplayAttackPolicy, ServerType},
    context::Context,
    crypto::{CipherCategory, CipherKind},
    relay::tcprelay::crypto_io::{CryptoRead, CryptoStream, CryptoWrite, StreamType},
};
use tokio::io::ReadBuf;

async fn write(stream: &mut CryptoStream<Cursor<Vec<u8>>>, data: &[u8]) -> usize {
    poll_fn(|cx| Pin::new(&mut *stream).poll_write_encrypted(cx, data))
        .await
        .unwrap()
}

async fn read(context: &Context, method: CipherKind, key: &[u8], wire: Vec<u8>) -> Result<Vec<u8>, ()> {
    let mut stream = CryptoStream::from_stream(context, Cursor::new(wire), StreamType::Server, method, key);
    let mut data = Vec::new();
    loop {
        let mut bytes = [0; 64];
        let mut buffer = ReadBuf::new(&mut bytes);
        poll_fn(|cx| Pin::new(&mut stream).poll_read_decrypted(cx, context, &mut buffer))
            .await
            .map_err(|_| ())?;
        if buffer.filled().is_empty() {
            return Ok(data);
        }
        data.extend_from_slice(buffer.filled());
    }
}

#[tokio::test]
async fn printable_salt_preserves_framing_authentication_and_replay_checks() {
    for method in [
        #[cfg(feature = "aead-cipher")]
        CipherKind::AES_256_GCM,
        #[cfg(feature = "aead-cipher")]
        CipherKind::CHACHA20_POLY1305,
        #[cfg(feature = "aead-cipher-2022")]
        CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
        #[cfg(feature = "aead-cipher-2022")]
        CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305,
        #[cfg(feature = "aead-cipher-2022-extra")]
        CipherKind::AEAD2022_BLAKE3_CHACHA8_POLY1305,
    ] {
        let mut context = Context::new(ServerType::Local);
        assert!(!context.printable_salt());
        context.set_printable_salt(true);
        let key = [1; 32];
        let mut stream = CryptoStream::from_stream(&context, Cursor::new(Vec::new()), StreamType::Client, method, &key);
        let salt = stream.sent_nonce().to_vec();
        assert_eq!(salt.len(), 32);
        assert!(salt[..6].iter().all(|byte| (0x20..=0x7e).contains(byte)));
        assert_eq!(write(&mut stream, &[]).await, 0);
        assert!(stream.get_ref().get_ref().is_empty());
        assert_eq!(write(&mut stream, b"first").await, 5);
        assert_eq!(write(&mut stream, b"second").await, 6);
        assert_eq!(stream.sent_nonce(), salt);
        let wire = stream.into_inner().into_inner();
        assert_eq!(&wire[..32], salt);
        let (headers, replay_protected) = match method.category() {
            #[cfg(feature = "aead-cipher")]
            CipherCategory::Aead => (4, cfg!(feature = "security-replay-attack-detect")),
            #[cfg(feature = "aead-cipher-2022")]
            CipherCategory::Aead2022 => (13, true),
            _ => unreachable!(),
        };
        assert_eq!(wire.len(), 32 + headers + 4 * method.tag_len() + 11);

        let mut server = Context::new(ServerType::Server);
        server.set_replay_attack_policy(ReplayAttackPolicy::Reject);
        assert_eq!(read(&server, method, &key, wire.clone()).await.unwrap(), b"firstsecond");
        if replay_protected {
            assert!(read(&server, method, &key, wire.clone()).await.is_err());
        }

        let mut tampered = wire.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let server = Context::new(ServerType::Server);
        assert!(read(&server, method, &key, tampered).await.is_err());
        assert!(read(&server, method, &[2; 32], wire).await.is_err());
    }
}

#[tokio::test]
#[cfg(feature = "aead-cipher")]
async fn printable_salt_is_client_only_and_rejects_unsupported_ciphers() {
    let mut context = Context::new(ServerType::Local);
    context.set_printable_salt(true);
    let key = [1; 16];
    let mut client = CryptoStream::from_stream(
        &context,
        Cursor::new(Vec::new()),
        StreamType::Client,
        CipherKind::AES_128_GCM,
        &key,
    );
    assert!(
        poll_fn(|cx| Pin::new(&mut client).poll_write_encrypted(cx, b"data"))
            .await
            .is_err()
    );
    assert!(client.get_ref().get_ref().is_empty());

    let mut server = CryptoStream::from_stream(
        &context,
        Cursor::new(Vec::new()),
        StreamType::Server,
        CipherKind::AES_128_GCM,
        &key,
    );
    assert_eq!(write(&mut server, b"data").await, 4);

    context.set_printable_salt(false);
    let mut client = CryptoStream::from_stream(
        &context,
        Cursor::new(Vec::new()),
        StreamType::Client,
        CipherKind::AES_128_GCM,
        &key,
    );
    assert_eq!(write(&mut client, b"data").await, 4);
}
