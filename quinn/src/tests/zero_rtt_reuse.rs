use super::*;
use crate::{Connection, ConnectionError, ReadError, StoppedError, WriteError};
use proto::{crypto, transport_parameters::TransportParameters};
use rustls::server::StoresServerSessions;
use std::{any::Any, future::poll_fn};
use tokio::{sync::oneshot, task::JoinHandle};

const DEADLINE: Duration = Duration::from_secs(5);
const PREFIX: &[u8] = b"0123456789abcdef";
const CRITICAL: [&[u8]; 3] = [b"\x00\x04\x00", b"\x02", b"\x03"];

struct TicketStore {
    inner: Arc<dyn StoresServerSessions>,
    hits: Arc<AtomicUsize>,
}

impl std::fmt::Debug for TicketStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TicketStore")
    }
}

impl StoresServerSessions for TicketStore {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.inner.put(key, value)
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get(key)
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        let result = self.inner.take(key);
        if result.is_some() {
            self.hits.fetch_add(1, Ordering::SeqCst);
        }
        result
    }

    fn can_cache(&self) -> bool {
        self.inner.can_cache()
    }
}

// Only this fixture knows that its ticket and resumed configuration share h3,
// certificate/store and key-exchange policy. Production rustls stays conservative.
struct FixtureCrypto {
    inner: Arc<dyn crypto::ClientConfig>,
    ticket_hits: Arc<AtomicUsize>,
}

impl crypto::ClientConfig for FixtureCrypto {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, proto::ConnectError> {
        let inner = self.inner.clone().start_session(version, name, params)?;
        let offered = inner.early_crypto().is_some();
        Ok(Box::new(FixtureSession {
            inner,
            offered,
            previous_hits: self.ticket_hits.load(Ordering::SeqCst),
            ticket_hits: self.ticket_hits.clone(),
        }))
    }
}

struct FixtureSession {
    inner: Box<dyn crypto::Session>,
    offered: bool,
    previous_hits: usize,
    ticket_hits: Arc<AtomicUsize>,
}

impl crypto::Session for FixtureSession {
    fn initial_keys(&self, cid: &proto::ConnectionId, side: proto::Side) -> crypto::Keys {
        self.inner.initial_keys(cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.inner.handshake_data()
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        self.inner.early_crypto()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.inner.early_data_accepted()
    }

    fn early_data_rejected(&self) -> bool {
        self.inner.early_data_rejected()
    }

    fn early_data_rejection_allows_stream_reuse(&self) -> bool {
        self.offered
            && !self.inner.is_handshaking()
            && self.inner.early_data_accepted() == Some(false)
            && self.ticket_hits.load(Ordering::SeqCst) > self.previous_hits
            && self
                .inner
                .handshake_data()
                .and_then(|data| data.downcast::<crypto::rustls::HandshakeData>().ok())
                .is_some_and(|data| data.protocol.as_deref() == Some(b"h3"))
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, data: &[u8]) -> Result<bool, proto::TransportError> {
        self.inner.read_handshake(data)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, proto::TransportError> {
        self.inner.transport_parameters()
    }

    fn write_handshake(&mut self, output: &mut Vec<u8>) -> Option<crypto::Keys> {
        self.inner.write_handshake(output)
    }

    fn next_1rtt_keys(&mut self) -> Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>> {
        self.inner.next_1rtt_keys()
    }

    fn is_valid_retry(&self, cid: &proto::ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.inner.is_valid_retry(cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), crypto::ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }
}

struct Fixture {
    client: Endpoint,
    server: Endpoint,
    hits: Arc<AtomicUsize>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.client.close(0u32.into(), b"fixture complete");
        self.server.close(0u32.into(), b"fixture complete");
    }
}

impl Fixture {
    fn peer_transport(grow_limits: bool) -> Arc<TransportConfig> {
        let mut transport = TransportConfig::default();
        transport
            .initial_rtt(Duration::from_millis(10))
            .max_concurrent_uni_streams(if grow_limits { 4u32 } else { 3u32 }.into())
            .max_concurrent_bidi_streams(3u32.into())
            .stream_receive_window(if grow_limits { 64u32 } else { 16u32 }.into())
            .receive_window(1024u32.into());
        Arc::new(transport)
    }

    async fn new(reuse: Option<bool>, grow_limits: bool) -> Self {
        let factory = EndpointFactory::new();
        let hits = Arc::new(AtomicUsize::new(0));
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![factory.cert.cert.der().clone()],
                PrivateKeyDer::Pkcs8(factory.cert.signing_key.serialize_der().into()),
            )
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.max_early_data_size = u32::MAX;
        tls.session_storage = Arc::new(TicketStore {
            inner: rustls::server::ServerSessionMemoryCache::new(32),
            hits: hits.clone(),
        });
        let mut rejected_tls = tls.clone();
        rejected_tls.max_early_data_size = 0;
        assert!(Arc::ptr_eq(
            &tls.session_storage,
            &rejected_tls.session_storage
        ));
        assert!(Arc::ptr_eq(&tls.cert_resolver, &rejected_tls.cert_resolver));
        let mut warm = crate::ServerConfig::with_crypto(Arc::new(
            crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
        ));
        warm.transport_config(Self::peer_transport(false));
        let mut rejected = warm.clone();
        rejected.crypto =
            Arc::new(crypto::rustls::QuicServerConfig::try_from(rejected_tls).unwrap());
        if grow_limits {
            rejected.transport_config(Self::peer_transport(true));
        }
        let server = Endpoint::server(warm, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(factory.cert.cert.der().clone()).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.enable_early_data = true;
        let mut config = ClientConfig::new(Arc::new(FixtureCrypto {
            inner: Arc::new(QuicClientConfig::try_from(tls).unwrap()),
            ticket_hits: hits.clone(),
        }));
        let mut transport = TransportConfig::default();
        transport
            .initial_rtt(Duration::from_millis(10))
            .send_window(64);
        if let Some(enabled) = reuse {
            transport.reuse_rejected_0rtt_streams(enabled);
        }
        config.transport_config(Arc::new(transport));
        let mut client = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        client.set_default_client_config(config);
        let fixture = Self {
            client,
            server,
            hits,
        };
        let (client, server) = join!(
            fixture
                .client
                .connect(fixture.server.local_addr().unwrap(), "localhost")
                .unwrap(),
            async { fixture.server.accept().await.unwrap().await.unwrap() }
        );
        let client = client.unwrap();
        let mut sent = server.open_uni().await.unwrap();
        sent.write_all(b"ticket-ready").await.unwrap();
        sent.finish().unwrap();
        let mut received = client.accept_uni().await.unwrap();
        assert_eq!(received.read_to_end(32).await.unwrap(), b"ticket-ready");
        assert_eq!(sent.stopped().await.unwrap(), None);
        client.close(0u32.into(), b"warm complete");
        let _ = server.closed().await;
        drop((client, server, sent, received));
        fixture.client.wait_idle().await;
        fixture.server.wait_idle().await;
        assert_eq!(fixture.hits.load(Ordering::SeqCst), 0);
        fixture.server.set_server_config(Some(rejected));
        fixture
    }

    fn resume(&self) -> (Connection, crate::ZeroRttAccepted) {
        self.client
            .connect(self.server.local_addr().unwrap(), "localhost")
            .unwrap()
            .into_0rtt()
            .unwrap_or_else(|_| panic!("warm connection must supply a real early-data ticket"))
    }

    async fn complete(&self, accepted: crate::ZeroRttAccepted) -> Connection {
        let (accepted, peer) = join!(accepted, async {
            self.server.accept().await.unwrap().await.unwrap()
        });
        assert!(!accepted, "retention must not report TLS acceptance");
        assert_eq!(self.hits.load(Ordering::SeqCst), 1);
        peer
    }

    async fn shutdown(&self) {
        self.client.close(0u32.into(), b"fixture complete");
        self.server.close(0u32.into(), b"fixture complete");
        self.client.wait_idle().await;
        self.server.wait_idle().await;
    }
}

fn pending<F>(future: F) -> (JoinHandle<F::Output>, oneshot::Receiver<()>)
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let (ready, registered) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut future = Box::pin(future);
        let mut ready = Some(ready);
        poll_fn(move |cx| {
            let result = future.as_mut().poll(cx);
            if let Some(ready) = ready.take() {
                assert!(
                    result.is_pending(),
                    "operation must register before handshake release"
                );
                let _ = ready.send(());
            }
            result
        })
        .await
    });
    (task, registered)
}

async fn early_sent(connection: &Connection) {
    while connection.stats().frame_tx.stream == 0 {
        tokio::task::yield_now().await;
    }
    assert!(!connection.rejected_0rtt_streams_reused());
}

#[tokio::test]
async fn zero_rtt_reuse_pending_io_and_critical_handles_continue() {
    timeout(DEADLINE, async {
        let fixture = Fixture::new(Some(true), true).await;
        let (connection, accepted) = fixture.resume();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        assert!(recv.is_0rtt());
        let request_id = send.id();
        send.write_all(PREFIX).await.unwrap();
        let mut critical = Vec::new();
        for bytes in CRITICAL {
            let mut stream = connection.open_uni().await.unwrap();
            stream.write_all(bytes).await.unwrap();
            critical.push(stream);
        }
        let (stopped, stop_ready) = pending(send.stopped());
        let (write, write_ready) = pending(async move {
            send.write_all(&[b'x'; 32]).await.unwrap();
            send.finish().unwrap();
            send
        });
        let (read, read_ready) = pending(async move {
            let data = recv.read_to_end(32).await.unwrap();
            (recv, data)
        });
        let (open, open_ready) = pending({
            let connection = connection.clone();
            async move { connection.open_uni().await.unwrap() }
        });
        for ready in [stop_ready, write_ready, read_ready, open_ready] {
            ready.await.unwrap();
        }
        early_sent(&connection).await;
        let peer = fixture.complete(accepted).await;
        assert!(connection.rejected_0rtt_streams_reused());
        // No peer application read may increase MAX_STREAM_DATA/MAX_STREAMS yet.
        let send = write.await.unwrap();
        let mut fourth = open.await.unwrap();
        assert_eq!(u64::from(fourth.id()), 14);
        fourth.write_all(b"new").await.unwrap();
        fourth.finish().unwrap();
        for stream in &mut critical {
            stream.finish().unwrap();
        }
        let (mut reply, mut request) = peer.accept_bi().await.unwrap();
        assert_eq!(request.id(), request_id);
        let mut expected = PREFIX.to_vec();
        expected.extend_from_slice(&[b'x'; 32]);
        assert_eq!(request.read_to_end(64).await.unwrap(), expected);
        reply.write_all(b"response").await.unwrap();
        reply.finish().unwrap();
        let (mut recv, data) = read.await.unwrap();
        assert_eq!(data, b"response");
        assert!(recv.is_0rtt(), "creation metadata remains stable");
        assert!(recv.read_chunk(1, true).await.unwrap().is_none());
        assert_eq!(stopped.await.unwrap().unwrap(), None);
        for (index, expected) in CRITICAL.into_iter().chain([b"new".as_slice()]).enumerate() {
            let mut received = peer.accept_uni().await.unwrap();
            assert_eq!(u64::from(received.id()), 2 + 4 * index as u64);
            assert_eq!(received.read_to_end(8).await.unwrap(), expected);
        }
        assert_eq!(send.id(), request_id);
        fixture.shutdown().await;
    })
    .await
    .expect("original early handles must progress on the resumed connection");
}

#[tokio::test]
async fn zero_rtt_reuse_peer_stop_and_reset_preserve_codes() {
    for code in [0u32, 256, 267, 268] {
        timeout(DEADLINE, async {
            let fixture = Fixture::new(Some(true), false).await;
            let (connection, accepted) = fixture.resume();
            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            send.write_all(PREFIX).await.unwrap();
            let (stopped, stop_ready) = pending(send.stopped());
            let (write, write_ready) = pending(async move { send.write_all(b"more").await });
            let (read, read_ready) = pending(async move { recv.read_chunk(32, true).await });
            let (mut adjacent_send, mut adjacent_recv) = connection.open_bi().await.unwrap();
            adjacent_send.write_all(b"adjacent").await.unwrap();
            adjacent_send.finish().unwrap();
            for ready in [stop_ready, write_ready, read_ready] {
                ready.await.unwrap();
            }
            early_sent(&connection).await;
            let peer = fixture.complete(accepted).await;
            assert!(connection.rejected_0rtt_streams_reused());
            let (mut reply, mut request) = peer.accept_bi().await.unwrap();
            request.stop(code.into()).unwrap();
            reply.reset(258u32.into()).unwrap();
            assert_eq!(stopped.await.unwrap().unwrap(), Some(code.into()));
            assert!(matches!(write.await.unwrap(), Err(WriteError::Stopped(value)) if value == code.into()));
            assert!(matches!(read.await.unwrap(), Err(ReadError::Reset(value)) if value == 258u32.into()));
            let (mut reply, mut request) = peer.accept_bi().await.unwrap();
            assert_eq!(u64::from(request.id()), 4);
            assert_eq!(request.read_to_end(32).await.unwrap(), b"adjacent");
            reply.write_all(b"ok").await.unwrap();
            reply.finish().unwrap();
            assert_eq!(adjacent_recv.read_to_end(8).await.unwrap(), b"ok");
            assert!(connection.close_reason().is_none());
            fixture.shutdown().await;
        })
        .await
        .expect("a peer stop must preserve its code and the adjacent stream");
    }
}

fn peer_closed(error: &ConnectionError) -> bool {
    matches!(error, ConnectionError::ApplicationClosed(close) if close.error_code == 42u32.into())
}

#[tokio::test]
async fn zero_rtt_reuse_late_close_keeps_original_error_and_history() {
    timeout(DEADLINE, async {
        let fixture = Fixture::new(Some(true), false).await;
        let (connection, accepted) = fixture.resume();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(PREFIX).await.unwrap();
        let (stopped, stop_ready) = pending(send.stopped());
        let (write, write_ready) = pending(async move { send.write_all(b"more").await });
        let (read, read_ready) = pending(async move { recv.read_chunk(32, true).await });
        let (closed, close_ready) = pending({
            let connection = connection.clone();
            async move { connection.closed().await }
        });
        for ready in [stop_ready, write_ready, read_ready, close_ready] {
            ready.await.unwrap();
        }
        early_sent(&connection).await;
        let peer = fixture.complete(accepted).await;
        assert!(connection.rejected_0rtt_streams_reused());
        peer.close(42u32.into(), b"late retained close");
        assert!(peer_closed(&closed.await.unwrap()));
        assert!(matches!(write.await.unwrap(), Err(WriteError::ConnectionLost(error)) if peer_closed(&error)));
        assert!(matches!(read.await.unwrap(), Err(ReadError::ConnectionLost(error)) if peer_closed(&error)));
        assert!(matches!(stopped.await.unwrap(), Err(StoppedError::ConnectionLost(error)) if peer_closed(&error)));
        assert!(connection.rejected_0rtt_streams_reused());
        assert!(peer_closed(&connection.close_reason().unwrap()));
        fixture.shutdown().await;
    })
    .await
    .expect("post-handshake closure must not turn into ZeroRttRejected");
}

#[tokio::test]
async fn zero_rtt_reuse_default_keeps_rejected_handle_contract() {
    timeout(DEADLINE, async {
        let fixture = Fixture::new(None, false).await;
        let (connection, accepted) = fixture.resume();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(PREFIX).await.unwrap();
        let (stopped, stop_ready) = pending(send.stopped());
        let (write, write_ready) = pending(async move { send.write_all(b"more").await });
        let (read, read_ready) = pending(async move { recv.read_chunk(32, true).await });
        for ready in [stop_ready, write_ready, read_ready] {
            ready.await.unwrap();
        }
        early_sent(&connection).await;
        let peer = fixture.complete(accepted).await;
        assert!(!connection.rejected_0rtt_streams_reused());
        assert!(matches!(
            write.await.unwrap(),
            Err(WriteError::ZeroRttRejected)
        ));
        assert!(matches!(
            read.await.unwrap(),
            Err(ReadError::ZeroRttRejected)
        ));
        assert!(matches!(
            stopped.await.unwrap(),
            Err(StoppedError::ZeroRttRejected)
        ));
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        assert_eq!(u64::from(send.id()), 0);
        assert!(!recv.is_0rtt());
        send.write_all(b"new").await.unwrap();
        send.finish().unwrap();
        let (mut reply, mut request) = peer.accept_bi().await.unwrap();
        assert_eq!(request.read_to_end(8).await.unwrap(), b"new");
        reply.write_all(b"ok").await.unwrap();
        reply.finish().unwrap();
        assert_eq!(recv.read_to_end(8).await.unwrap(), b"ok");
        fixture.shutdown().await;
    })
    .await
    .expect("default rejection must retain the existing public contract");
}
