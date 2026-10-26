//! Outbound UDP relay through a SOCKS5-only proxy chain.
//!
//! Establishes a SOCKS5 `UDP ASSOCIATE` against every hop in the
//! configured chain, then transports each datagram by nesting one
//! [`UdpAssociateHeader`] per hop. The resulting [`OutboundProxyDatagram`]
//! implements [`DatagramSocket`] / [`DatagramSend`] / [`DatagramReceive`]
//! so it can be plugged directly into [`ProxySocket::from_socket`] in
//! place of a raw UDP socket.
//!
//! Supported only when **every** hop is SOCKS5 (see
//! [`OutboundProxyClient::supports_udp`]). Callers decide whether to use
//! this transport; ssserver rejects incompatible chains for UDP listeners.

use std::{
    io::{self, Cursor},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll, ready},
};

use bytes::{BufMut, BytesMut};
use log::{debug, trace};
use shadowsocks::{
    context::SharedContext,
    lookup_then,
    net::{ConnectOpts, TcpStream as ShadowTcpStream, UdpSocket as ShadowUdpSocket},
    relay::{
        socks5::{Address, UdpAssociateHeader},
        udprelay::{DatagramReceive, DatagramSend, DatagramSocket},
    },
};
use tokio::io::{AsyncRead, ReadBuf};

use super::{
    OutboundProxyClient, OutboundProxyKind, TcpDialer, chain::connect_chain_for_udp_associate,
    socks5::Socks5Negotiator,
    stream::OutboundProxyStream,
};

/// One SOCKS5 UDP relay hop. The `assoc_tcp` keep-alive connection must
/// outlive every datagram exchanged through this hop (RFC 1928).
struct Socks5UdpRelay {
    /// Keep-alive TCP control connection. We hold the bare [`ShadowTcpStream`]
    /// rather than an [`super::OutboundProxyStream`] so the relay (and
    /// therefore [`OutboundProxyDatagram`]) is `Sync` — the chain builder
    /// never produces a non-TCP variant for SOCKS5-only chains, so this
    /// downcast always succeeds.
    assoc_tcp: Mutex<ShadowTcpStream>,
    relay_addr: Address,
}

impl Socks5UdpRelay {
    fn relay_addr(&self) -> &Address {
        &self.relay_addr
    }
}

/// Multi-hop SOCKS5 UDP relay implementing the
/// [`DatagramSocket`] / [`DatagramSend`] / [`DatagramReceive`] triple.
///
/// The chain is built once at association time. Fixed-target callers use
/// the datagram traits; server relays use `send_to` / `recv_from` to retain
/// each datagram's destination and source address.
pub struct OutboundProxyDatagram {
    socket: ShadowUdpSocket,
    relays: Vec<Socks5UdpRelay>,
    target: Option<Address>,
    /// Address the local UDP socket is `connect()`ed to (the first hop's
    /// relay address). Reported to upper layers as the "peer" / source
    /// from which `recv_from` returns datagrams.
    first_hop_addr: SocketAddr,
    /// Reusable receive scratch buffer (header stripping requires reading
    /// the full datagram before we know the payload offset).
    recv_scratch: Mutex<Vec<u8>>,
}

/// A rejected datagram does not invalidate the SOCKS5 control connections.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
struct UdpPacketError(io::Error);

impl OutboundProxyDatagram {
    /// Establish UDP relays through every hop of `client`.
    ///
    /// * `target` is the inner-most destination (typically the ss-server's
    ///   UDP external address).
    /// * `dialer` is used to dial all TCP control connections.
    /// * `connect_opts` configures the local UDP socket.
    pub async fn associate<D>(
        client: &OutboundProxyClient,
        context: &SharedContext,
        dialer: &D,
        connect_opts: &ConnectOpts,
        target: Address,
    ) -> io::Result<Self>
    where
        D: TcpDialer + Sync,
    {
        Self::associate_inner(client, context, dialer, connect_opts, Some(target)).await
    }

    pub(crate) async fn associate_relay<D>(
        client: &OutboundProxyClient,
        context: &SharedContext,
        dialer: &D,
        connect_opts: &ConnectOpts,
    ) -> io::Result<Self>
    where
        D: TcpDialer + Sync,
    {
        Self::associate_inner(client, context, dialer, connect_opts, None).await
    }

    async fn associate_inner<D>(
        client: &OutboundProxyClient,
        context: &SharedContext,
        dialer: &D,
        connect_opts: &ConnectOpts,
        target: Option<Address>,
    ) -> io::Result<Self>
    where
        D: TcpDialer + Sync,
    {
        let hops = client.hops();
        if hops.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty outbound proxy chain",
            ));
        }
        for hop in hops {
            if !matches!(hop.kind, OutboundProxyKind::Socks5 { .. }) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "outbound UDP relay requires every hop to be SOCKS5",
                ));
            }
        }

        let first_tcp = dialer.dial(&hops[0].addr).await?;
        let first_peer = first_tcp.peer_addr()?;
        let mut first_tcp = Some(first_tcp);
        let mut relays: Vec<Socks5UdpRelay> = Vec::with_capacity(hops.len());

        // The externally visible source port is unknown behind NAT, and a
        // previous relay may use a different socket for its outbound traffic.
        // RFC 1928 permits an all-zero address/port in this case.
        let announce = Address::from(SocketAddr::new(
            if first_peer.is_ipv4() {
                Ipv4Addr::UNSPECIFIED.into()
            } else {
                Ipv6Addr::UNSPECIFIED.into()
            },
            0,
        ));
        for (idx, hop) in hops.iter().enumerate() {
            let mut tcp = if idx == 0 {
                OutboundProxyStream::from_tcp(first_tcp.take().expect("first TCP connection"))?
            } else {
                connect_chain_for_udp_associate(hops, idx, dialer).await?
            };

            let auth = match &hop.kind {
                OutboundProxyKind::Socks5 { auth } => auth,
                _ => unreachable!("guarded above"),
            };

            let resp = Socks5Negotiator::establish_udp_associate(&mut tcp, announce.clone(), auth)
                .await
                .map_err(io::Error::other)?;

            // For a SOCKS5-only chain the byte stream is always still raw
            // TCP after the handshake (no TLS / HTTP layers were
            // applied). Recover the underlying TcpStream so the relay
            // struct stays `Sync`.
            let tcp = tcp.try_into_tcp().map_err(|_| {
                io::Error::other(
                    "internal error: outbound UDP relay produced a non-TCP keep-alive stream",
                )
            })?;

            // Some proxies return an unspecified BND.ADDR. For the first
            // hop use its connected peer; later hop names stay unresolved
            // and are carried to the preceding proxy in the UDP header.
            let relay_addr = match resp.address {
                Address::SocketAddress(sa) if sa.ip().is_unspecified() => {
                    let port = sa.port();
                    if idx == 0 {
                        Address::from(SocketAddr::new(first_peer.ip(), port))
                    } else {
                        match &hop.addr {
                            Address::SocketAddress(sa) => Address::from(SocketAddr::new(sa.ip(), port)),
                            Address::DomainNameAddress(name, _) => Address::DomainNameAddress(name.clone(), port),
                        }
                    }
                }
                addr => addr,
            };
            if relay_addr.port() == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SOCKS5 UDP relay returned port zero",
                ));
            }
            trace!(
                "outbound udp hop {}: relay_addr={}, announce={}",
                idx, relay_addr, announce
            );
            relays.push(Socks5UdpRelay {
                assoc_tcp: Mutex::new(tcp),
                relay_addr,
            });
        }

        // Only the directly contacted relay needs local DNS resolution.
        let first_hop_addr = match relays[0].relay_addr() {
            Address::SocketAddress(sa) => *sa,
            Address::DomainNameAddress(name, port) => {
                lookup_then!(context, name, *port, |sa| { Ok::<SocketAddr, io::Error>(sa) })?.0
            }
        };

        // Connect the local UDP socket to the first hop so subsequent
        // sends can use `send` instead of `send_to`.
        let socket = ShadowUdpSocket::connect_with_opts(&first_hop_addr, connect_opts).await?;

        debug!(
            "outbound udp chain established: {} hop(s), first_hop={}, target={:?}",
            relays.len(),
            first_hop_addr,
            target,
        );

        Ok(Self {
            socket,
            relays,
            target,
            first_hop_addr,
            recv_scratch: Mutex::new(Vec::new()),
        })
    }

    /// Number of SOCKS5 hops the chain consists of.
    pub fn hop_count(&self) -> usize {
        self.relays.len()
    }

    /// Wrap `payload` in N nested SOCKS5 UDP headers, where N is the
    /// number of hops. The inner-most header carries `target`.
    fn encode(&self, target: &Address, payload: &[u8]) -> BytesMut {
        let n = self.relays.len();

        // Header[i] addr = relays[i+1].relay_addr() for i < n-1, or
        // target for i == n-1.
        let mut total = payload.len();
        for i in 0..n {
            let addr = if i + 1 < n {
                self.relays[i + 1].relay_addr()
            } else {
                target
            };
            total += UdpAssociateHeader::new(0, addr.clone()).serialized_len();
        }

        let mut buf = BytesMut::with_capacity(total);
        for i in 0..n {
            let addr = if i + 1 < n {
                self.relays[i + 1].relay_addr().clone()
            } else {
                target.clone()
            };
            UdpAssociateHeader::new(0, addr).write_to_buf(&mut buf);
        }
        buf.put_slice(payload);
        buf
    }

    /// Strip N nested SOCKS5 UDP headers from a freshly received datagram.
    /// Returns the inner-most reported source address and the payload
    /// offset.
    fn decode(&self, recv_buf: &[u8]) -> io::Result<(Address, usize)> {
        let n = self.relays.len();
        let mut cur = Cursor::new(recv_buf);
        let mut last_addr: Option<Address> = None;

        for _ in 0..n {
            let pos = cur.position() as usize;
            if recv_buf.get(pos..pos + 2) != Some(&[0, 0]) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid SOCKS5 UDP reserved bytes",
                ));
            }
            // `UdpAssociateHeader::read_from` is async over an
            // `AsyncRead`. Cursor's `AsyncRead` impl yields synchronously,
            // so polling the future once always completes.
            let fut = std::pin::pin!(UdpAssociateHeader::read_from(&mut cur));
            match futures::FutureExt::now_or_never(fut) {
                Some(Ok(h)) if h.frag == 0 => last_addr = Some(h.address),
                Some(Ok(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "fragmented SOCKS5 UDP datagram",
                    ));
                }
                Some(Err(err)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("outbound udp: failed to parse SOCKS5 UDP header: {err}"),
                    ));
                }
                None => unreachable!("Cursor read_from should be synchronous"),
            }
        }

        let pos = cur.position() as usize;
        Ok((last_addr.expect("relays is non-empty"), pos))
    }

    /// Send to an arbitrary target without resolving domain names locally.
    pub async fn send_to(&self, payload: &[u8], target: &Address) -> io::Result<usize> {
        let wire = self.encode(target, payload);
        tokio::select! {
            biased;
            err = self.control_closed() => Err(err),
            sent = self.socket.send(&wire) => {
                if sent.map_err(Self::datagram_error)? != wire.len() {
                    return Err(Self::packet_error(io::ErrorKind::WriteZero.into()));
                }
                Ok(payload.len())
            }
        }
    }

    /// Receive a datagram together with the final relay's reported source.
    /// Monitor all control connections even while there is no UDP traffic.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Address)> {
        let n = tokio::select! {
            biased;
            err = self.control_closed() => return Err(err),
            result = self.socket.recv(buf) => result.map_err(Self::datagram_error)?,
        };
        let (addr, pos) = self.decode(&buf[..n]).map_err(Self::packet_error)?;
        buf.copy_within(pos..n, 0);
        Ok((n - pos, addr))
    }

    pub(crate) fn is_packet_error(err: &io::Error) -> bool {
        err.get_ref().is_some_and(|err| err.is::<UdpPacketError>())
    }

    fn packet_error(err: io::Error) -> io::Error {
        io::Error::new(err.kind(), UdpPacketError(err))
    }

    fn datagram_error(err: io::Error) -> io::Error {
        let too_large = match err.raw_os_error() {
            #[cfg(unix)]
            Some(libc::EMSGSIZE) => true,
            #[cfg(windows)]
            Some(windows_sys::Win32::Networking::WinSock::WSAEMSGSIZE) => true,
            _ => false,
        };
        if too_large || matches!(err.kind(), io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData) {
            Self::packet_error(err)
        } else {
            err
        }
    }

    async fn control_closed(&self) -> io::Error {
        futures::future::poll_fn(|cx| {
            for relay in &self.relays {
                let mut tcp = relay.assoc_tcp.lock().expect("SOCKS5 control connection poisoned");
                let mut byte = [0];
                let mut buf = ReadBuf::new(&mut byte);
                match Pin::new(&mut *tcp).poll_read(cx, &mut buf) {
                    Poll::Pending => {}
                    Poll::Ready(Err(err)) => return Poll::Ready(err),
                    Poll::Ready(Ok(())) => {
                        return Poll::Ready(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "SOCKS5 UDP control connection closed or received unexpected data",
                        ));
                    }
                }
            }
            Poll::Pending
        })
        .await
    }

    fn poll_recv_addr(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<Address>> {
        let mut scratch = self.recv_scratch.lock().expect("recv scratch poisoned");
        // Receive the whole wire datagram, including all nested headers.
        if scratch.is_empty() {
            scratch.resize(shadowsocks::relay::udprelay::MAXIMUM_UDP_PAYLOAD_SIZE, 0);
        }
        let mut tmp = ReadBuf::new(&mut scratch);
        ready!(self.socket.poll_recv(cx, &mut tmp))?;
        let n = tmp.filled().len();
        let (addr, pos) = self.decode(&scratch[..n])?;
        if n - pos > buf.remaining() {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::InvalidData)));
        }
        buf.put_slice(&scratch[pos..n]);
        Poll::Ready(Ok(addr))
    }
}

impl DatagramSocket for OutboundProxyDatagram {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

impl DatagramSend for OutboundProxyDatagram {
    fn poll_send(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let Some(target) = self.target.as_ref() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP relay requires a target address",
            )));
        };
        let wire = self.encode(target, buf);
        let sent = ready!(self.socket.poll_send(cx, &wire))?;
        if sent == wire.len() {
            // Report the upper-layer payload size (matches what
            // ProxySocket expects from a direct UDP send).
            Poll::Ready(Ok(buf.len()))
        } else {
            Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)))
        }
    }

    fn poll_send_to(&self, cx: &mut Context<'_>, buf: &[u8], _target: SocketAddr) -> Poll<io::Result<usize>> {
        // The first-hop relay is what we actually send to on the wire;
        // the upper layer's `target` (typically the ss-server) is already
        // baked into the inner-most SOCKS5 UDP header via `self.target`.
        let _ = _target;
        self.poll_send(cx, buf)
    }

    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx)
    }
}

impl DatagramReceive for OutboundProxyDatagram {
    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_recv_addr(cx, buf))?;
        Poll::Ready(Ok(()))
    }

    fn poll_recv_from(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<SocketAddr>> {
        // The upper layer wants the source address. We report the first-
        // hop relay we actually received from (the only socket-level
        // address available); the inner-most SOCKS5 source is discarded
        // because the upper layer will decrypt and parse the ss-server's
        // own packet header anyway.
        ready!(self.poll_recv(cx, buf))?;
        Poll::Ready(Ok(self.first_hop_addr))
    }

    fn poll_recv_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_recv_ready(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadowsocks::{
        config::ServerType,
        context::Context as SsContext,
        relay::socks5::{Command, HandshakeRequest, HandshakeResponse, Reply, TcpRequestHeader, TcpResponseHeader},
    };
    use tokio::{
        net::{TcpListener, UdpSocket},
        sync::oneshot,
        time::{Duration, timeout},
    };

    struct TestDialer;

    impl TcpDialer for TestDialer {
        async fn dial(&self, addr: &Address) -> io::Result<ShadowTcpStream> {
            let Address::SocketAddress(addr) = addr else {
                unreachable!()
            };
            ShadowTcpStream::connect_with_opts(addr, &ConnectOpts::default()).await
        }
    }

    #[tokio::test]
    async fn udp_relay_preserves_addresses_and_control_lifetime() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy =
            crate::config::OutboundProxy::from_url(&format!("socks5://{}", listener.local_addr().unwrap())).unwrap();
        let client = OutboundProxyClient::from_config(&[proxy]);
        let context = SsContext::new_shared(ServerType::Server);
        let (close_tx, close_rx) = oneshot::channel();
        let targets = [
            "127.0.0.1:1234".parse::<SocketAddr>().unwrap().into(),
            "[::1]:4321".parse::<SocketAddr>().unwrap().into(),
            Address::DomainNameAddress("unresolved.invalid".into(), 53),
        ];
        let expected = targets.clone();
        let proxy_task = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            HandshakeRequest::read_from(&mut tcp).await.unwrap();
            HandshakeResponse::new(0).write_to(&mut tcp).await.unwrap();
            let request = TcpRequestHeader::read_from(&mut tcp).await.unwrap();
            assert!(matches!(request.command, Command::UdpAssociate));
            assert_eq!(request.address.port(), 0);
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay = SocketAddr::from(([0, 0, 0, 0], udp.local_addr().unwrap().port()));
            TcpResponseHeader::new(Reply::Succeeded, relay.into())
                .write_to(&mut tcp)
                .await
                .unwrap();
            let mut packet = [0u8; 1024];
            for target in expected {
                let (n, peer) = udp.recv_from(&mut packet).await.unwrap();
                let mut cur = Cursor::new(&packet[..n]);
                let header = UdpAssociateHeader::read_from(&mut cur).await.unwrap();
                assert_eq!(header.address, target);
                assert_eq!(&packet[cur.position() as usize..n], b"payload");
                udp.send_to(&packet[..n], peer).await.unwrap();
            }
            close_rx.await.unwrap();
        });
        let relay = timeout(
            Duration::from_secs(2),
            client.associate_udp_relay(&context, &TestDialer, &ConnectOpts::default()),
        )
        .await
        .unwrap()
        .unwrap();
        let mut packet = [0u8; 1024];
        let err = relay.send_to(&vec![0; 65536], &targets[0]).await.unwrap_err();
        assert!(OutboundProxyDatagram::is_packet_error(&err));
        assert!(!OutboundProxyDatagram::is_packet_error(&io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid association response",
        )));
        for target in targets.clone() {
            relay.send_to(b"payload", &target).await.unwrap();
            let (n, source) = timeout(Duration::from_secs(2), relay.recv_from(&mut packet))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(source, target);
            assert_eq!(&packet[..n], b"payload");
        }
        // Fragmented and malformed responses must not be treated as payload.
        assert!(relay.decode(&[0, 0, 1, 1, 127, 0, 0, 1, 0, 53]).is_err());
        assert!(relay.decode(&[1, 0, 0, 1, 127, 0, 0, 1, 0, 53]).is_err());
        assert!(relay.decode(&[0, 0, 0, 4]).is_err());
        close_tx.send(()).unwrap();
        proxy_task.await.unwrap();
        let err = timeout(Duration::from_secs(2), relay.recv_from(&mut packet))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(!OutboundProxyDatagram::is_packet_error(&err));
        assert!(relay.send_to(b"closed", &targets[0]).await.is_err());
    }
}
