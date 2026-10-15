use super::*;
use crate::{AsyncUdpSocket, UdpPoller};
use std::{
    future::poll_fn,
    io::IoSliceMut,
    pin::Pin,
    sync::{Mutex, atomic::AtomicBool},
};
use tokio::{sync::oneshot, task::JoinHandle};

const DEADLINE: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug)]
enum FailureSite {
    PollWritable = 1,
    TrySend = 2,
}

impl FailureSite {
    fn message(self) -> &'static str {
        match self {
            Self::PollWritable => "injected poll_writable permission failure",
            Self::TrySend => "injected try_send permission failure",
        }
    }
}

#[derive(Debug)]
struct FailingSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    armed: AtomicUsize,
    failures: AtomicUsize,
    capture_send: Mutex<Option<Arc<CloseReceiptGate>>>,
    require_receipt: Mutex<Option<Arc<CloseReceiptGate>>>,
}

#[derive(Debug, Default)]
struct CloseReceiptGate {
    ciphertext: Mutex<Option<Vec<u8>>>,
    received: AtomicBool,
}

impl FailingSocket {
    fn bind() -> Arc<Self> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket.set_nonblocking(true).unwrap();
        Arc::new(Self {
            inner: crate::Runtime::wrap_udp_socket(&TokioRuntime, socket).unwrap(),
            armed: AtomicUsize::new(0),
            failures: AtomicUsize::new(0),
            capture_send: Mutex::new(None),
            require_receipt: Mutex::new(None),
        })
    }

    fn fail_if_armed(&self, site: FailureSite) -> io::Result<()> {
        if self
            .require_receipt
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|gate| !gate.received.load(Ordering::SeqCst))
        {
            return Ok(());
        }
        if self
            .armed
            .compare_exchange(site as usize, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.failures.fetch_add(1, Ordering::SeqCst);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                site.message(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct FailingPoller {
    socket: Arc<FailingSocket>,
    inner: Pin<Box<dyn UdpPoller>>,
}

impl UdpPoller for FailingPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.socket.fail_if_armed(FailureSite::PollWritable) {
            return Poll::Ready(Err(error));
        }
        this.inner.as_mut().poll_writable(cx)
    }
}

impl AsyncUdpSocket for FailingSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(FailingPoller {
            inner: self.inner.clone().create_io_poller(),
            socket: self,
        })
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        self.fail_if_armed(FailureSite::TrySend)?;
        if let Some(gate) = self.capture_send.lock().unwrap().as_ref() {
            gate.ciphertext
                .lock()
                .unwrap()
                .get_or_insert_with(|| transmit.contents.to_vec());
        }
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let result = self.inner.poll_recv(cx, bufs, meta);
        if let Poll::Ready(Ok(count)) = &result {
            if let Some(gate) = self.require_receipt.lock().unwrap().as_ref() {
                let expected = gate.ciphertext.lock().unwrap();
                if let Some(expected) = expected.as_ref() {
                    for (buf, meta) in bufs.iter().zip(meta.iter()).take(*count) {
                        let stride = if meta.stride == 0 {
                            meta.len
                        } else {
                            meta.stride
                        };
                        if stride != 0
                            && buf[..meta.len]
                                .chunks(stride)
                                .any(|packet| packet == expected)
                        {
                            gate.received.store(true, Ordering::SeqCst);
                        }
                    }
                }
            }
        }
        result
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

fn spawn_pending<F>(future: F) -> (JoinHandle<F::Output>, oneshot::Receiver<()>)
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
                    "observer must wait before fault injection"
                );
                let _ = ready.send(());
            }
            result
        })
        .await
    });
    (task, registered)
}

#[derive(Debug)]
struct Observation {
    causes: [Option<crate::ConnectionError>; 4],
    idle_notified: bool,
}

impl Observation {
    fn all_notified(&self) -> bool {
        self.idle_notified && self.causes.iter().all(Option::is_some)
    }

    fn original_cause_preserved(&self, site: FailureSite) -> bool {
        self.causes.iter().all(|error| {
            error
                .as_ref()
                .is_some_and(|error| original_cause(error, site))
        })
    }
}

fn original_cause(error: &crate::ConnectionError, site: FailureSite) -> bool {
    matches!(error, crate::ConnectionError::TransportError(error)
        if error.code == proto::TransportErrorCode::INTERNAL_ERROR
            && error.reason.contains(site.message()))
}

fn small_window_transport() -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport
        .mtu_discovery_config(None)
        .stream_receive_window(64u32.into())
        .receive_window(128u32.into())
        .send_window(64)
        .max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
    transport
}

fn endpoints() -> (Endpoint, Endpoint, Arc<FailingSocket>) {
    let factory = EndpointFactory::new();
    let server_ep = factory.endpoint_with_config(small_window_transport());
    let mut roots = RootCertStore::empty();
    roots.add(factory.cert.cert.der().clone()).unwrap();
    let mut config = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    config.transport_config(Arc::new(small_window_transport()));
    let socket = FailingSocket::bind();
    let mut client_ep = Endpoint::new_with_abstract_socket(
        factory.endpoint_config.clone(),
        None,
        socket.clone(),
        Arc::new(TokioRuntime),
    )
    .unwrap();
    client_ep.set_default_client_config(config);
    (client_ep, server_ep, socket)
}

async fn connect(
    client_ep: &Endpoint,
    server_ep: &Endpoint,
) -> (crate::Connection, crate::Connection) {
    let (client, server) = timeout(Duration::from_secs(3), async {
        join!(
            client_ep
                .connect(server_ep.local_addr().unwrap(), "localhost")
                .unwrap(),
            async { server_ep.accept().await.unwrap().await }
        )
    })
    .await
    .unwrap();
    (client.unwrap(), server.unwrap())
}

async fn observe_failure(site: FailureSite) -> Observation {
    let (client_ep, server_ep, socket) = endpoints();
    let (client, server) = connect(&client_ep, &server_ep).await;
    let retained_client = client.clone();
    let (mut upload, mut response) = client.open_bi().await.unwrap();
    upload.write_all(b"x").await.unwrap();
    let (reply, mut request) = timeout(DEADLINE, server.accept_bi())
        .await
        .unwrap()
        .unwrap();
    let mut prefix = [0];
    timeout(DEADLINE, request.read_exact(&mut prefix))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&prefix, b"x");

    let stopped = upload.stopped();
    let closed_client = client.clone();
    let idle_endpoint = client_ep.clone();
    let (mut closed_task, closed_ready) =
        spawn_pending(async move { closed_client.closed().await });
    let (mut read_task, read_ready) = spawn_pending(async move {
        let mut byte = [0];
        response.read(&mut byte).await
    });
    let (mut write_task, write_ready) =
        spawn_pending(async move { upload.write_all(&vec![0x61; 8192]).await });
    let (mut stopped_task, stopped_ready) = spawn_pending(stopped);
    let (mut idle_task, idle_ready) = spawn_pending(async move { idle_endpoint.wait_idle().await });
    timeout(DEADLINE, async {
        let ready = join!(
            closed_ready,
            read_ready,
            write_ready,
            stopped_ready,
            idle_ready
        );
        ready.0.unwrap();
        ready.1.unwrap();
        ready.2.unwrap();
        ready.3.unwrap();
        ready.4.unwrap();
    })
    .await
    .unwrap();

    socket.armed.store(site as usize, Ordering::SeqCst);
    client
        .send_datagram(Bytes::from_static(b"fault trigger"))
        .unwrap();
    timeout(DEADLINE, async {
        while socket.failures.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the selected real runtime I/O path must consume the fault");
    let (closed, read, write, stopped, idle) = join!(
        timeout(DEADLINE, &mut closed_task),
        timeout(DEADLINE, &mut read_task),
        timeout(DEADLINE, &mut write_task),
        timeout(DEADLINE, &mut stopped_task),
        timeout(DEADLINE, &mut idle_task),
    );
    eprintln!(
        "hard I/O {site:?}: injected={}, closed={closed:?}, read={read:?}, write={write:?}, stopped={stopped:?}, idle={idle:?}",
        socket.failures.load(Ordering::SeqCst)
    );
    assert_eq!(socket.failures.load(Ordering::SeqCst), 1);
    let observation = Observation {
        causes: [
            closed.ok().map(Result::unwrap),
            match read {
                Ok(Ok(Err(crate::ReadError::ConnectionLost(error)))) => Some(error),
                _ => None,
            },
            match write {
                Ok(Ok(Err(crate::WriteError::ConnectionLost(error)))) => Some(error),
                _ => None,
            },
            match stopped {
                Ok(Ok(Err(crate::StoppedError::ConnectionLost(error)))) => Some(error),
                _ => None,
            },
        ],
        idle_notified: matches!(idle, Ok(Ok(()))),
    };

    // Baseline failures must not leave detached observers holding the endpoints.
    closed_task.abort();
    read_task.abort();
    write_task.abort();
    stopped_task.abort();
    idle_task.abort();
    drop((closed_task, read_task, write_task, stopped_task, idle_task));
    drop((reply, request, retained_client, client));
    server.close(0u32.into(), b"fixture cleanup");
    drop(server);
    client_ep.close(0u32.into(), b"fixture cleanup");
    server_ep.close(0u32.into(), b"fixture cleanup");
    timeout(Duration::from_secs(3), async {
        join!(client_ep.wait_idle(), server_ep.wait_idle());
    })
    .await
    .expect("fixture cleanup after observer cancellation");
    observation
}

#[tokio::test]
async fn io_failure_poll_writable_notifies_all_live_handles() {
    let observation = observe_failure(FailureSite::PollWritable).await;
    assert!(
        observation.all_notified(),
        "pending observers lost driver failure: {observation:?}"
    );
    assert!(
        observation.original_cause_preserved(FailureSite::PollWritable),
        "original I/O cause was replaced: {observation:?}"
    );
}

#[tokio::test]
async fn io_failure_try_send_notifies_all_live_handles() {
    let observation = observe_failure(FailureSite::TrySend).await;
    assert!(
        observation.all_notified(),
        "pending observers lost driver failure: {observation:?}"
    );
    assert!(
        observation.original_cause_preserved(FailureSite::TrySend),
        "original I/O cause was replaced: {observation:?}"
    );
}

#[tokio::test]
async fn io_failure_initial_packet_preserves_connecting_and_handshake_error() {
    for site in [FailureSite::PollWritable, FailureSite::TrySend] {
        let (client_ep, server_ep, socket) = endpoints();
        socket.armed.store(site as usize, Ordering::SeqCst);
        let mut connecting = client_ep
            .connect(server_ep.local_addr().unwrap(), "localhost")
            .unwrap();
        let handshake_error = match timeout(DEADLINE, connecting.handshake_data())
            .await
            .unwrap()
        {
            Ok(_) => panic!("failed Initial must not yield handshake data"),
            Err(error) => error,
        };
        assert!(
            original_cause(&handshake_error, site),
            "handshake cause: {handshake_error:?}"
        );
        timeout(DEADLINE, client_ep.wait_idle())
            .await
            .expect("failed Initial must leave endpoint idle while Connecting remains alive");
        assert_eq!(client_ep.open_connections(), 0);
        let connect_error = timeout(DEADLINE, connecting).await.unwrap().unwrap_err();
        assert!(
            original_cause(&connect_error, site),
            "Connecting cause: {connect_error:?}"
        );
        assert_eq!(socket.failures.load(Ordering::SeqCst), 1);
        assert_eq!(server_ep.open_connections(), 0);
        server_ep.close(0u32.into(), b"fixture cleanup");
        timeout(DEADLINE, server_ep.wait_idle()).await.unwrap();
    }
}

async fn round_trip_marker(
    client: &crate::Connection,
    server: &crate::Connection,
    marker: &'static [u8],
) {
    timeout(DEADLINE, async {
        let (mut send, mut receive) = client.open_bi().await.unwrap();
        send.write_all(marker).await.unwrap();
        send.finish().unwrap();
        let (mut reply, mut request) = server.accept_bi().await.unwrap();
        assert_eq!(request.read_to_end(64).await.unwrap(), marker);
        reply.write_all(marker).await.unwrap();
        reply.finish().unwrap();
        assert_eq!(receive.read_to_end(64).await.unwrap(), marker);
    })
    .await
    .expect("the replacement connection must remain usable");
}

#[tokio::test]
async fn io_failure_dropping_old_handles_does_not_drain_reused_endpoint_slot() {
    for site in [FailureSite::PollWritable, FailureSite::TrySend] {
        let (client_ep, server_ep, socket) = endpoints();
        let (old_client, old_server) = connect(&client_ep, &server_ep).await;
        let retained = old_client.clone();
        let (mut old_send, old_receive) = old_client.open_bi().await.unwrap();
        old_send.write_all(b"old").await.unwrap();
        let (old_reply, mut old_request) = timeout(DEADLINE, old_server.accept_bi())
            .await
            .unwrap()
            .unwrap();
        let mut prefix = [0; 3];
        timeout(DEADLINE, old_request.read_exact(&mut prefix))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&prefix, b"old");
        socket.armed.store(site as usize, Ordering::SeqCst);
        old_client
            .send_datagram(Bytes::from_static(b"fault trigger"))
            .unwrap();
        let error = timeout(DEADLINE, old_client.closed()).await.unwrap();
        assert!(
            original_cause(&error, site),
            "old connection cause: {error:?}"
        );
        timeout(DEADLINE, client_ep.wait_idle()).await.unwrap();
        assert_eq!(client_ep.open_connections(), 0);

        let (new_client, new_server) = connect(&client_ep, &server_ep).await;
        round_trip_marker(&new_client, &new_server, b"before old drop").await;
        assert_eq!(client_ep.open_connections(), 1);
        drop((old_send, old_receive, retained, old_client));
        // Yield so any erroneous second Drained notification can reach Endpoint.
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        round_trip_marker(&new_client, &new_server, b"after old drop").await;
        assert_eq!(client_ep.open_connections(), 1);
        assert!(new_client.close_reason().is_none());
        assert_eq!(socket.failures.load(Ordering::SeqCst), 1);
        drop((old_reply, old_request));
        old_server.close(0u32.into(), b"old peer cleanup");
        new_client.close(0u32.into(), b"fixture cleanup");
        new_server.close(0u32.into(), b"fixture cleanup");
        client_ep.close(0u32.into(), b"fixture cleanup");
        server_ep.close(0u32.into(), b"fixture cleanup");
        timeout(Duration::from_secs(3), async {
            join!(client_ep.wait_idle(), server_ep.wait_idle());
        })
        .await
        .expect("replacement connection fixture cleanup");
    }
}

#[tokio::test]
async fn io_failure_while_sending_close_preserves_existing_terminal_reason() {
    for site in [FailureSite::PollWritable, FailureSite::TrySend] {
        let (client_ep, server_ep, socket) = endpoints();
        let (client, server) = connect(&client_ep, &server_ep).await;
        let retained = client.clone();
        socket.armed.store(site as usize, Ordering::SeqCst);
        client.close(41u32.into(), b"local close before I/O error");
        assert!(matches!(
            timeout(DEADLINE, client.closed()).await.unwrap(),
            crate::ConnectionError::LocallyClosed
        ));
        timeout(DEADLINE, async {
            while socket.failures.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("Close transmit must encounter the injected hard error");
        timeout(DEADLINE, client_ep.wait_idle()).await.unwrap();
        assert!(matches!(
            retained.close_reason(),
            Some(crate::ConnectionError::LocallyClosed)
        ));
        assert_eq!(client_ep.open_connections(), 0);
        assert_eq!(socket.failures.load(Ordering::SeqCst), 1);
        drop((retained, client));
        server.close(0u32.into(), b"fixture cleanup");
        server_ep.close(0u32.into(), b"fixture cleanup");
        timeout(Duration::from_secs(3), server_ep.wait_idle())
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn io_failure_close_reply_preserves_pending_peer_terminal_reason() {
    for site in [FailureSite::PollWritable, FailureSite::TrySend] {
        let (client_ep, server_ep, socket) = endpoints();
        let server_socket = FailingSocket::bind();
        server_ep.rebind_abstract(server_socket.clone()).unwrap();
        let (client, server) = connect(&client_ep, &server_ep).await;
        let retained = client.clone();
        let gate = Arc::new(CloseReceiptGate::default());
        *socket.require_receipt.lock().unwrap() = Some(gate.clone());
        socket.armed.store(site as usize, Ordering::SeqCst);
        server.close(42u32.into(), b"peer close before reply I/O error");
        // Both operations are synchronous in this current-thread test: the next
        // server datagram is generated after close, and only its receipt arms I/O.
        *server_socket.capture_send.lock().unwrap() = Some(gate.clone());
        let error = timeout(DEADLINE, client.closed()).await.unwrap();
        eprintln!(
            "peer-close fault {site:?}: error={error:?}, rx_close={}, injected={}",
            client.stats().frame_rx.connection_close,
            socket.failures.load(Ordering::SeqCst)
        );
        assert!(gate.received.load(Ordering::SeqCst));
        assert!(client.stats().frame_rx.connection_close > 0);
        assert!(gate.ciphertext.lock().unwrap().is_some());
        assert!(
            matches!(error, crate::ConnectionError::ApplicationClosed(close) if close.error_code.into_inner() == 42),
            "pending peer-close reason must win over the reply write error"
        );
        timeout(DEADLINE, async {
            while socket.failures.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("peer-close reply must encounter the injected hard error");
        timeout(DEADLINE, client_ep.wait_idle()).await.unwrap();
        assert!(matches!(
            retained.close_reason(),
            Some(crate::ConnectionError::ApplicationClosed(close)) if close.error_code.into_inner() == 42
        ));
        assert_eq!(client_ep.open_connections(), 0);
        assert_eq!(socket.failures.load(Ordering::SeqCst), 1);
        drop((retained, client));
        server_ep.close(0u32.into(), b"fixture cleanup");
        timeout(Duration::from_secs(3), server_ep.wait_idle())
            .await
            .unwrap();
    }
}
