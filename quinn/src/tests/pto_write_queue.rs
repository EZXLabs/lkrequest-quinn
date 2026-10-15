//! Exact-source-inspired transport test, not an installed-Chrome capture.

use super::*;
use crate::{AsyncTimer, AsyncUdpSocket, UdpPoller};
use std::{
    io::IoSliceMut,
    pin::Pin,
    sync::{Mutex, Weak},
};

#[derive(Debug)]
struct Clock {
    now: Mutex<Instant>,
    timers: Mutex<Vec<Weak<Mutex<TimerState>>>>,
}

#[derive(Debug)]
struct TimerState {
    owner: &'static str,
    deadline: Instant,
    waker: Option<Waker>,
}

impl Clock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            now: Mutex::new(Instant::now()),
            timers: Mutex::new(Vec::new()),
        })
    }

    fn now(&self) -> Instant {
        *self.now.lock().unwrap()
    }

    fn client_deadline(&self) -> Instant {
        let timers = self
            .timers
            .lock()
            .unwrap()
            .iter()
            .filter_map(Weak::upgrade)
            .collect::<Vec<_>>();
        let deadlines = timers
            .iter()
            .filter_map(|timer| {
                let timer = timer.lock().unwrap();
                (timer.owner == "client").then_some(timer.deadline)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            deadlines.len(),
            1,
            "one real connection timer must identify the next deadline"
        );
        deadlines[0]
    }

    fn advance_to(&self, deadline: Instant) {
        assert!(deadline >= self.now());
        *self.now.lock().unwrap() = deadline;
        let timers = self
            .timers
            .lock()
            .unwrap()
            .iter()
            .filter_map(Weak::upgrade)
            .collect::<Vec<_>>();
        for timer in timers {
            let wake = {
                let mut timer = timer.lock().unwrap();
                (timer.deadline <= deadline)
                    .then(|| timer.waker.take())
                    .flatten()
            };
            if let Some(wake) = wake {
                wake.wake();
            }
        }
    }
}

#[derive(Debug)]
struct Timer {
    clock: Arc<Clock>,
    state: Arc<Mutex<TimerState>>,
}

impl AsyncTimer for Timer {
    fn reset(self: Pin<&mut Self>, deadline: Instant) {
        self.state.lock().unwrap().deadline = deadline;
    }
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        let fresh = cx.waker().clone();
        let mut state = self.state.lock().unwrap();
        if state.deadline <= self.clock.now() {
            return Poll::Ready(());
        }
        let old = state.waker.replace(fresh);
        drop(state);
        drop(old);
        Poll::Pending
    }
}

#[derive(Debug)]
struct TestRuntime(Arc<Clock>, &'static str);

impl crate::Runtime for TestRuntime {
    fn new_timer(&self, deadline: Instant) -> Pin<Box<dyn AsyncTimer>> {
        let state = Arc::new(Mutex::new(TimerState {
            owner: self.1,
            deadline,
            waker: None,
        }));
        self.0.timers.lock().unwrap().push(Arc::downgrade(&state));
        Box::pin(Timer {
            clock: self.0.clone(),
            state,
        })
    }
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }
    fn wrap_udp_socket(&self, socket: UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        crate::Runtime::wrap_udp_socket(&TokioRuntime, socket)
    }
    fn now(&self) -> Instant {
        self.0.now()
    }
}

#[derive(Debug)]
struct Attempt {
    bytes: Vec<u8>,
    blocked: bool,
    sent: bool,
}

#[derive(Debug, Default)]
struct Gate {
    armed: bool,
    blocked: bool,
    drop_sends: bool,
    hard_error: bool,
    attempts: Vec<Attempt>,
    waiters: Vec<Weak<Mutex<Option<Waker>>>>,
}

#[derive(Debug)]
struct Socket {
    inner: Arc<dyn AsyncUdpSocket>,
    gate: Mutex<Gate>,
}

impl Socket {
    fn bind() -> Arc<Self> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket.set_nonblocking(true).unwrap();
        Arc::new(Self {
            inner: crate::Runtime::wrap_udp_socket(&TokioRuntime, socket).unwrap(),
            gate: Mutex::new(Gate::default()),
        })
    }

    fn release(&self) {
        let waiters = {
            let mut gate = self.gate.lock().unwrap();
            gate.armed = false;
            gate.blocked = false;
            gate.waiters
                .iter()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>()
        };
        for waiter in waiters {
            let wake = waiter.lock().unwrap().take();
            if let Some(wake) = wake {
                wake.wake();
            }
        }
    }
}

#[derive(Debug)]
struct Poller {
    socket: Arc<Socket>,
    inner: Pin<Box<dyn UdpPoller>>,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl UdpPoller for Poller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let fresh = cx.waker().clone();
        let gate = this.socket.gate.lock().unwrap();
        if gate.blocked {
            let old = this.waker.lock().unwrap().replace(fresh);
            drop(gate);
            drop(old);
            return Poll::Pending;
        }
        drop(gate);
        this.inner.as_mut().poll_writable(cx)
    }
}

impl AsyncUdpSocket for Socket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        let waker = Arc::new(Mutex::new(None));
        self.gate
            .lock()
            .unwrap()
            .waiters
            .push(Arc::downgrade(&waker));
        Box::pin(Poller {
            inner: self.inner.clone().create_io_poller(),
            socket: self,
            waker,
        })
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        if self.gate.lock().unwrap().hard_error {
            return Err(io::Error::other("fixture hard write failure"));
        }
        let (index, blocked, dropped) = {
            let mut gate = self.gate.lock().unwrap();
            let blocked = gate.armed;
            gate.blocked |= blocked;
            let index = gate.attempts.len();
            gate.attempts.push(Attempt {
                bytes: transmit.contents.to_vec(),
                blocked,
                sent: false,
            });
            (index, blocked, gate.drop_sends)
        };
        if blocked {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if dropped {
            return Ok(());
        }
        let result = self.inner.try_send(transmit);
        if result.is_ok() {
            self.gate.lock().unwrap().attempts[index].sent = true;
        }
        result
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
    fn max_transmit_segments(&self) -> usize {
        1
    }
}

async fn settle() {
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    // Allow real loopback readiness to reach the driver; this does not advance
    // the clock used by any QUIC timer.
    sleep(Duration::from_millis(2)).await;
}

async fn until(mut ready: impl FnMut() -> bool) {
    timeout(Duration::from_secs(3), async {
        while !ready() {
            settle().await;
        }
    })
    .await
    .expect("expected real driver event did not arrive");
}

fn endpoints(
    clock: Arc<Clock>,
    chrome_profile: bool,
    queue_enabled: bool,
) -> (Endpoint, Endpoint, Arc<Socket>, Arc<Socket>) {
    let factory = EndpointFactory::new();
    let mut transport = TransportConfig::default();
    transport
        .mtu_discovery_config(None)
        .ack_obligation_only(chrome_profile)
        .pto_single_probe_with_gap(chrome_profile)
        .chrome_pto_timing(chrome_profile)
        .queue_pto_while_blocked(queue_enabled)
        .max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
    let transport = Arc::new(transport);
    let key = PrivateKeyDer::Pkcs8(factory.cert.signing_key.serialize_der().into());
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![factory.cert.cert.der().clone()], key)
        .unwrap();
    tls.send_tls13_tickets = 0;
    let mut server_config = crate::ServerConfig::with_crypto(Arc::new(
        proto::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    server_config.transport_config(transport.clone());
    let mut roots = RootCertStore::empty();
    roots.add(factory.cert.cert.der().clone()).unwrap();
    let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    client_config.transport_config(transport);
    let client_socket = Socket::bind();
    let server_socket = Socket::bind();
    let mut endpoint_config = EndpointConfig::default();
    endpoint_config.cid_generator(|| Box::new(RandomConnectionIdGenerator::new(0)));
    let mut client = Endpoint::new_with_abstract_socket(
        endpoint_config,
        None,
        client_socket.clone(),
        Arc::new(TestRuntime(clock.clone(), "client")),
    )
    .unwrap();
    client.set_default_client_config(client_config);
    let server = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(server_config),
        server_socket.clone(),
        Arc::new(TestRuntime(clock, "server")),
    )
    .unwrap();
    (client, server, client_socket, server_socket)
}

#[derive(Debug)]
struct Observation {
    generated_before_block: u64,
    generated_at_block: u64,
    generated_after_timers: u64,
    fired_deadlines: usize,
    successful_held_completions: usize,
    queued_probes: usize,
    new_cids_before: u64,
    new_cids_after: u64,
    pings_before: u64,
    pings_after: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Completion {
    Recover,
    LocalClose,
    PeerClose,
    HardError,
}

async fn blocked_probe(
    chrome_profile: bool,
    queue_enabled: bool,
    completion: Completion,
) -> Observation {
    let clock = Clock::new();
    let (client_ep, server_ep, client_socket, server_socket) =
        endpoints(clock.clone(), chrome_profile, queue_enabled);
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
    let client = client.unwrap();
    let server = server.unwrap();
    clock.advance_to(clock.now() + Duration::from_millis(50));
    settle().await;
    assert!(
        client.stats().frame_rx.handshake_done > 0,
        "the blocked probe fixture must be handshake-confirmed"
    );
    // Establish a real ACK boundary before withholding any server sends. A
    // scheduler turn alone does not prove startup control packets were ACKed.
    let mut warm = client.open_uni().await.unwrap();
    warm.write_all(b"warm").await.unwrap();
    warm.finish().unwrap();
    let mut warm_peer = timeout(Duration::from_secs(3), server.accept_uni())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(3), warm_peer.read_to_end(16))
            .await
            .unwrap()
            .unwrap(),
        b"warm"
    );
    let stopped = warm.stopped();
    tokio::pin!(stopped);
    let completion_result = timeout(Duration::from_secs(3), async {
        loop {
            tokio::select! {
                result = &mut stopped => break result,
                _ = sleep(Duration::from_millis(2)) => {
                    clock.advance_to(clock.now() + Duration::from_millis(50));
                }
            }
        }
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        completion_result, None,
        "warm FIN must be acknowledged, not stopped"
    );
    assert_eq!(
        client.stats().frame_tx.new_connection_id,
        0,
        "both controls use the Chrome client zero-length CID path"
    );

    // Retain a second outstanding stream, matching PtoAndWriteBlocked's
    // decisive difference from its neighboring one-canceled-stream control.
    server_socket.gate.lock().unwrap().drop_sends = true;
    let (mut canceled, mut response) = client.open_bi().await.unwrap();
    canceled.write_all(b"cancel").await.unwrap();
    let (mut reply, mut canceled_peer) = timeout(Duration::from_secs(3), server.accept_bi())
        .await
        .unwrap()
        .unwrap();
    let mut prefix = [0; 6];
    canceled_peer.read_exact(&mut prefix).await.unwrap();
    assert_eq!(&prefix, b"cancel");
    let mut surviving = client.open_uni().await.unwrap();
    surviving.write_all(b"survive").await.unwrap();
    let mut surviving_peer = timeout(Duration::from_secs(3), server.accept_uni())
        .await
        .unwrap()
        .unwrap();
    let mut prefix = [0; 7];
    surviving_peer.read_exact(&mut prefix).await.unwrap();
    assert_eq!(&prefix, b"survive");
    let generated_before_block =
        client.stats().frame_tx.stream + client.stats().frame_tx.reset_stream;
    client_socket.gate.lock().unwrap().armed = true;
    canceled.reset(268u32.into()).unwrap();
    until(|| client_socket.gate.lock().unwrap().blocked).await;
    let generated_at_block = client.stats().frame_tx.stream + client.stats().frame_tx.reset_stream;
    let new_cids_before = client.stats().frame_tx.new_connection_id;
    let pings_before = client.stats().frame_tx.ping;
    assert_eq!(generated_at_block, generated_before_block + 1);
    let held = {
        let gate = client_socket.gate.lock().unwrap();
        let blocked = gate
            .attempts
            .iter()
            .filter(|attempt| attempt.blocked)
            .collect::<Vec<_>>();
        assert_eq!(blocked.len(), 1);
        assert_eq!(
            blocked[0].bytes[0] & 0x80,
            0,
            "hold an actual 1-RTT datagram"
        );
        blocked[0].bytes.clone()
    };
    let start = clock.now();
    let mut fired_deadlines = 0;
    for _ in 0..8 {
        let deadline = clock.client_deadline();
        if deadline > start + Duration::from_secs(3) {
            break;
        }
        assert!(deadline > clock.now(), "only drive newly armed deadlines");
        clock.advance_to(deadline);
        settle().await;
        fired_deadlines += 1;
    }
    let generated_after_timers =
        client.stats().frame_tx.stream + client.stats().frame_tx.reset_stream;
    let new_cids_after = client.stats().frame_tx.new_connection_id;
    let pings_after = client.stats().frame_tx.ping;
    assert!(
        fired_deadlines > 0,
        "a real armed timer must fire during the block"
    );
    assert_eq!(
        client_socket
            .gate
            .lock()
            .unwrap()
            .attempts
            .iter()
            .filter(|attempt| attempt.blocked)
            .count(),
        1,
        "blocked readiness must prevent a socket retry loop"
    );
    assert!(client.close_reason().is_none() && server.close_reason().is_none());
    let queued = client.pto_queue_ciphertexts_for_test();
    if queue_enabled {
        assert!(
            !queued.is_empty(),
            "the armed timer must commit at least one queued probe"
        );
    } else {
        assert!(queued.is_empty());
    }

    server_socket.gate.lock().unwrap().drop_sends = false;
    match completion {
        Completion::Recover => {
            client_socket.release();
            until(|| {
                client_socket
                    .gate
                    .lock()
                    .unwrap()
                    .attempts
                    .iter()
                    .any(|attempt| attempt.sent && attempt.bytes == held)
            })
            .await;
            let mut byte = [0];
            assert!(
                matches!(timeout(Duration::from_secs(3), canceled_peer.read(&mut byte)).await.unwrap(), Err(crate::ReadError::Reset(code)) if code.into_inner() == 268)
            );
            surviving.write_all(b"/tail").await.unwrap();
            surviving.finish().unwrap();
            assert_eq!(
                timeout(Duration::from_secs(3), surviving_peer.read_to_end(32))
                    .await
                    .unwrap()
                    .unwrap(),
                b"/tail"
            );
            reply.write_all(b"response survives").await.unwrap();
            reply.finish().unwrap();
            assert_eq!(
                timeout(Duration::from_secs(3), response.read_to_end(64))
                    .await
                    .unwrap()
                    .unwrap(),
                b"response survives"
            );
            let gate = client_socket.gate.lock().unwrap();
            let completed: Vec<_> = gate
                .attempts
                .iter()
                .filter(|attempt| attempt.sent)
                .map(|attempt| &attempt.bytes)
                .collect();
            let start = completed
                .iter()
                .position(|bytes| bytes.as_slice() == held.as_slice())
                .unwrap();
            let expected: Vec<_> = std::iter::once(&held).chain(queued.iter()).collect();
            assert_eq!(
                &completed[start..start + expected.len()],
                expected.as_slice(),
                "lower-writer completion must precede every committed FIFO item"
            );
            for bytes in &queued {
                assert_eq!(
                    completed
                        .iter()
                        .filter(|sent| sent.as_slice() == bytes.as_slice())
                        .count(),
                    1
                );
            }
        }
        Completion::LocalClose => {
            client.close(41u32.into(), b"local terminal");
            until(|| client.close_reason().is_some()).await;
            assert!(matches!(
                client.close_reason(),
                Some(crate::ConnectionError::LocallyClosed)
            ));
            client_socket.release();
        }
        Completion::PeerClose => {
            server.close(42u32.into(), b"peer terminal");
            until(|| client.close_reason().is_some()).await;
            assert!(
                matches!(client.close_reason(), Some(crate::ConnectionError::ApplicationClosed(reason)) if reason.error_code.into_inner() == 42)
            );
            client_socket.release();
        }
        Completion::HardError => {
            client_socket.gate.lock().unwrap().hard_error = true;
            client_socket.release();
            until(|| client.close_reason().is_some()).await;
            assert!(
                matches!(client.close_reason(), Some(crate::ConnectionError::TransportError(reason)) if reason.code == proto::TransportErrorCode::INTERNAL_ERROR)
            );
            client_socket.gate.lock().unwrap().hard_error = false;
        }
    }
    settle().await;
    assert!(client.pto_queue_ciphertexts_for_test().is_empty());
    if completion != Completion::Recover {
        let gate = client_socket.gate.lock().unwrap();
        assert!(
            gate.attempts
                .iter()
                .filter(|attempt| attempt.sent)
                .all(|attempt| attempt.bytes != held && !queued.contains(&attempt.bytes)),
            "terminal cleanup must abandon both the original pending datagram and queued probes"
        );
    }
    let successful_held_completions = client_socket
        .gate
        .lock()
        .unwrap()
        .attempts
        .iter()
        .filter(|attempt| attempt.sent && attempt.bytes == held)
        .count();
    client_ep.close(0u32.into(), b"done");
    server_ep.close(0u32.into(), b"done");
    settle().await;
    clock.advance_to(clock.now() + Duration::from_secs(60));
    timeout(Duration::from_secs(3), async {
        join!(client_ep.wait_idle(), server_ep.wait_idle());
    })
    .await
    .unwrap();
    let result = Observation {
        generated_before_block,
        generated_at_block,
        generated_after_timers,
        fired_deadlines,
        successful_held_completions,
        queued_probes: queued.len(),
        new_cids_before,
        new_cids_after,
        pings_before,
        pings_after,
    };
    eprintln!(
        "PTO queue chrome_profile={chrome_profile} queue_enabled={queue_enabled}: {result:?}"
    );
    result
}

#[tokio::test]
async fn pto_write_queue_chrome_commits_probe_behind_blocked_writer() {
    let result = blocked_probe(true, true, Completion::Recover).await;
    eprintln!(
        "probe frame diagnostics: NEW_CONNECTION_ID {} -> {}, PING {} -> {}",
        result.new_cids_before, result.new_cids_after, result.pings_before, result.pings_after
    );
    assert_eq!(result.successful_held_completions, 1);
    assert_eq!(result.generated_at_block, result.generated_before_block + 1);
    assert!(result.fired_deadlines > 0);
    assert!(result.queued_probes > 0);
    assert!(
        result.generated_after_timers > result.generated_at_block,
        "exact QUICHE PtoAndWriteBlocked requires a later probe committed while the lower writer is still blocked: {result:?}"
    );
}

#[tokio::test]
async fn pto_write_queue_legacy_keeps_one_lower_writer_buffer() {
    let result = blocked_probe(false, false, Completion::Recover).await;
    assert_eq!(result.successful_held_completions, 1);
    assert_eq!(result.generated_after_timers, result.generated_at_block);
    assert_eq!(result.queued_probes, 0);
}

#[tokio::test]
async fn pto_write_queue_terminal_cleanup_abandons_fifo_on_local_close() {
    let result = blocked_probe(true, true, Completion::LocalClose).await;
    assert!(result.queued_probes > 0);
    assert_eq!(result.successful_held_completions, 0);
}

#[tokio::test]
async fn pto_write_queue_terminal_cleanup_abandons_fifo_on_peer_close() {
    let result = blocked_probe(true, true, Completion::PeerClose).await;
    assert!(result.queued_probes > 0);
    assert_eq!(result.successful_held_completions, 0);
}

#[tokio::test]
async fn pto_write_queue_terminal_cleanup_abandons_fifo_on_hard_error() {
    let result = blocked_probe(true, true, Completion::HardError).await;
    assert!(result.queued_probes > 0);
    assert_eq!(result.successful_held_completions, 0);
}

#[tokio::test]
async fn pto_write_queue_disabled_with_other_chrome_options_keeps_single_buffer() {
    let result = blocked_probe(true, false, Completion::Recover).await;
    assert_eq!(result.successful_held_completions, 1);
    assert_eq!(result.generated_after_timers, result.generated_at_block);
    assert_eq!(result.queued_probes, 0);
}
