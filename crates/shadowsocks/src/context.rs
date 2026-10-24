//! Shadowsocks service context

use std::{io, net::SocketAddr, sync::Arc};

use byte_string::ByteStr;
use log::warn;

use crate::{
    config::{ReplayAttackPolicy, ServerType},
    crypto::CipherKind,
    dns_resolver::DnsResolver,
    security::replay::ReplayProtector,
};

/// Service context
#[derive(Debug)]
pub struct Context {
    // Protector against replay attack
    // The actual replay detection behavior is implemented in ReplayProtector
    replay_protector: ReplayProtector,
    // Policy against replay attack
    replay_policy: ReplayAttackPolicy,

    // hickory-dns resolver, which supports REAL asynchronous resolving, and also customizable
    dns_resolver: Arc<DnsResolver>,

    // Connect IPv6 address first
    ipv6_first: bool,
    printable_salt: bool,
    tcp_popcount: bool,
}

/// `Context` for sharing between services
pub type SharedContext = Arc<Context>;

impl Context {
    /// Create a new `Context` for `Client` or `Server`
    pub fn new(config_type: ServerType) -> Self {
        Self {
            replay_protector: ReplayProtector::new(config_type),
            replay_policy: ReplayAttackPolicy::Default,
            dns_resolver: Arc::new(DnsResolver::system_resolver()),
            ipv6_first: false,
            printable_salt: false,
            tcp_popcount: false,
        }
    }

    /// Create a new `Context` shared
    pub fn new_shared(config_type: ServerType) -> SharedContext {
        SharedContext::new(Self::new(config_type))
    }

    /// Check if nonce exist or not
    ///
    /// If not, set into the current bloom filter
    #[cfg(any(feature = "stream-cipher", feature = "aead-cipher", feature = "aead-cipher-2022"))]
    #[inline(always)]
    fn check_nonce_and_set(&self, method: CipherKind, nonce: &[u8]) -> bool {
        match self.replay_policy {
            ReplayAttackPolicy::Ignore => false,
            _ => self.replay_protector.check_nonce_and_set(method, nonce),
        }
    }

    /// Generate nonce (IV or SALT)
    pub fn generate_nonce(&self, method: CipherKind, nonce: &mut [u8], unique: bool) {
        self.generate_nonce_with_prefix(method, nonce, unique, false);
    }

    pub(crate) fn generate_nonce_with_prefix(
        &self,
        method: CipherKind,
        nonce: &mut [u8],
        unique: bool,
        printable: bool,
    ) {
        let _ = printable;
        if nonce.is_empty() {
            return;
        }

        #[cfg(any(feature = "stream-cipher", feature = "aead-cipher", feature = "aead-cipher-2022"))]
        loop {
            use crate::crypto::utils::random_iv_or_salt;

            random_iv_or_salt(nonce);

            #[cfg(any(feature = "aead-cipher", feature = "aead-cipher-2022"))]
            if printable && Self::supports_printable_salt(method) {
                use rand::RngExt;

                let mut rng = rand::rng();
                let length = rng.random_range(6..=12);
                for byte in &mut nonce[..length] {
                    *byte = rng.random_range(0x20..=0x7e);
                }
            }

            // Salt already exists, generate a new one.
            if unique && self.check_nonce_and_set(method, nonce) {
                continue;
            }

            break;
        }

        #[cfg(not(any(feature = "stream-cipher", feature = "aead-cipher", feature = "aead-cipher-2022")))]
        if !nonce.is_empty() {
            let _ = unique;
            panic!("{method} don't know how to generate nonce");
        }
    }

    /// Check nonce replay
    pub fn check_nonce_replay(&self, method: CipherKind, nonce: &[u8]) -> io::Result<()> {
        if nonce.is_empty() {
            return Ok(());
        }

        #[allow(unused_mut)]
        let mut replay_policy = self.replay_policy;

        #[cfg(feature = "aead-cipher-2022")]
        if method.is_aead_2022() {
            // AEAD-2022 can't be ignored.
            replay_policy = ReplayAttackPolicy::Reject;
        }

        match replay_policy {
            ReplayAttackPolicy::Default | ReplayAttackPolicy::Ignore => Ok(()),
            ReplayAttackPolicy::Detect => {
                if self.replay_protector.check_nonce_and_set(method, nonce) {
                    warn!("detected repeated nonce (iv/salt) {:?}", ByteStr::new(nonce));
                }
                Ok(())
            }
            ReplayAttackPolicy::Reject => {
                if self.replay_protector.check_nonce_and_set(method, nonce) {
                    let err = io::Error::other("detected repeated nonce (iv/salt)");
                    Err(err)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Enable experimental printable salts for outgoing client TCP streams.
    pub fn set_printable_salt(&mut self, enabled: bool) {
        self.printable_salt = enabled;
    }

    /// Whether printable client TCP salts are enabled.
    pub fn printable_salt(&self) -> bool {
        self.printable_salt
    }

    /// Enable the initial TCP request ciphertext transform on both peers.
    pub fn set_tcp_popcount(&mut self, enabled: bool) {
        self.tcp_popcount = enabled;
    }

    /// Whether the initial TCP request ciphertext transform is enabled.
    pub fn tcp_popcount(&self) -> bool {
        self.tcp_popcount
    }

    /// Whether the cipher provides authenticated TCP framing for the transform.
    pub fn supports_tcp_popcount(method: CipherKind) -> bool {
        match method.category() {
            #[cfg(feature = "aead-cipher")]
            crate::crypto::CipherCategory::Aead => true,
            #[cfg(feature = "aead-cipher-2022")]
            crate::crypto::CipherCategory::Aead2022 => true,
            _ => false,
        }
    }

    /// Whether the cipher supports the printable salt experiment.
    pub fn supports_printable_salt(method: CipherKind) -> bool {
        match method {
            #[cfg(feature = "aead-cipher")]
            CipherKind::AES_256_GCM | CipherKind::CHACHA20_POLY1305 => true,
            #[cfg(feature = "aead-cipher-2022")]
            CipherKind::AEAD2022_BLAKE3_AES_256_GCM | CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 => true,
            #[cfg(feature = "aead-cipher-2022-extra")]
            CipherKind::AEAD2022_BLAKE3_CHACHA8_POLY1305 => true,
            _ => false,
        }
    }

    /// Set a DNS resolver
    ///
    /// The resolver should be wrapped in an `Arc`, because it could be shared with the other servers
    pub fn set_dns_resolver(&mut self, resolver: Arc<DnsResolver>) {
        self.dns_resolver = resolver;
    }

    /// Get the DNS resolver
    pub fn dns_resolver(&self) -> &Arc<DnsResolver> {
        &self.dns_resolver
    }

    /// Resolves DNS address to `SocketAddr`s
    pub async fn dns_resolve<'a>(
        &self,
        addr: &'a str,
        port: u16,
    ) -> io::Result<impl Iterator<Item = SocketAddr> + 'a + use<'a>> {
        self.dns_resolver.resolve(addr, port).await
    }

    /// Try to connect IPv6 addresses first if hostname could be resolved to both IPv4 and IPv6
    pub fn set_ipv6_first(&mut self, ipv6_first: bool) {
        self.ipv6_first = ipv6_first;
    }

    /// Try to connect IPv6 addresses first if hostname could be resolved to both IPv4 and IPv6
    pub fn ipv6_first(&self) -> bool {
        self.ipv6_first
    }

    /// Set policy against replay attack
    pub fn set_replay_attack_policy(&mut self, replay_policy: ReplayAttackPolicy) {
        self.replay_policy = replay_policy;
    }

    /// Get policy against replay attack
    pub fn replay_attack_policy(&self) -> ReplayAttackPolicy {
        self.replay_policy
    }
}
