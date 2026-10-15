use super::*;
#[path = "blocked_close.rs"]
mod blocked_close;
use crate::{AsyncTimer, AsyncUdpSocket, UdpPoller};
use std::{
    io::IoSliceMut,
    pin::Pin,
    sync::{Mutex, Weak},
};

#[derive(Debug)]
struct Clock {
    state: Mutex<ClockState>,
    tasks: AtomicUsize,
}

#[derive(Debug)]
struct ClockState {
    now: Instant,
    timers: Vec<Weak<Mutex<TimerState>>>,
}

#[derive(Debug)]
struct TimerState {
    deadline: Instant,
    waker: Option<Waker>,
    owner: &'static str,
}

impl Clock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ClockState {
                now: Instant::now(),
                timers: Vec::new(),
            }),
            tasks: AtomicUsize::new(0),
        })
    }

    fn now(&self) -> Instant {
        self.state.lock().unwrap().now
    }

    fn deadline(&self, owner: &str) -> Instant {
        let timers = self
            .state
            .lock()
            .unwrap()
            .timers
            .iter()
            .filter_map(Weak::upgrade)
            .collect::<Vec<_>>();
        let matching = timers
            .iter()
            .filter_map(|timer| {
                let timer = timer.lock().unwrap();
                (timer.owner == owner).then_some(timer.deadline)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            matching.len(),
            1,
            "fixture must have one connection timer for {owner}"
        );
        matching[0]
    }

    fn advance(&self, elapsed: Duration) {
        let (now, timers) = {
            let mut state = self.state.lock().unwrap();
            state.now += elapsed;
            state.timers.retain(|timer| timer.strong_count() > 0);
            (
                state.now,
                state
                    .timers
                    .iter()
                    .filter_map(Weak::upgrade)
                    .collect::<Vec<_>>(),
            )
        };
        for timer in timers {
            let wake = {
                let mut timer = timer.lock().unwrap();
                (timer.deadline <= now)
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
struct TestTimer {
    clock: Arc<Clock>,
    state: Arc<Mutex<TimerState>>,
}

impl AsyncTimer for TestTimer {
    fn reset(self: Pin<&mut Self>, deadline: Instant) {
        self.state.lock().unwrap().deadline = deadline;
    }

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        let waker = cx.waker().clone();
        let mut state = self.state.lock().unwrap();
        if state.deadline <= self.clock.now() {
            return Poll::Ready(());
        }
        let old = state.waker.replace(waker);
        drop(state);
        drop(old);
        Poll::Pending
    }
}

#[derive(Debug)]
struct TestRuntime(Arc<Clock>, &'static str);

struct TaskGuard(Arc<Clock>);

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.tasks.fetch_sub(1, Ordering::SeqCst);
    }
}

impl crate::Runtime for TestRuntime {
    fn new_timer(&self, deadline: Instant) -> Pin<Box<dyn AsyncTimer>> {
        let state = Arc::new(Mutex::new(TimerState {
            deadline,
            waker: None,
            owner: self.1,
        }));
        self.0
            .state
            .lock()
            .unwrap()
            .timers
            .push(Arc::downgrade(&state));
        Box::pin(TestTimer {
            clock: self.0.clone(),
            state,
        })
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.0.tasks.fetch_add(1, Ordering::SeqCst);
        let guard = TaskGuard(self.0.clone());
        tokio::spawn(async move {
            let _guard = guard;
            future.await;
        });
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
    ciphertext: Vec<u8>,
    blocked: bool,
    dropped: bool,
    sent: bool,
}

#[derive(Debug, Default)]
struct GateState {
    armed: bool,
    blocked: bool,
    drop_sends: bool,
    recv_paused: bool,
    recv_waker: Option<Waker>,
    attempts: Vec<Attempt>,
    pollers: Vec<Weak<Mutex<Option<Waker>>>>,
    send_error: Option<io::ErrorKind>,
    poll_error: Option<io::ErrorKind>,
    pending_polls: usize,
    injected_errors: usize,
}

#[derive(Debug)]
struct GateSocket {
    socket: Arc<dyn AsyncUdpSocket>,
    state: Mutex<GateState>,
}

impl GateSocket {
    fn bind() -> Arc<Self> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket.set_nonblocking(true).unwrap();
        Arc::new(Self {
            socket: crate::Runtime::wrap_udp_socket(&TokioRuntime, socket).unwrap(),
            state: Mutex::new(GateState::default()),
        })
    }

    fn arm(&self) {
        self.state.lock().unwrap().armed = true;
    }

    fn release(&self) {
        let waiters = {
            let mut state = self.state.lock().unwrap();
            state.armed = false;
            state.blocked = false;
            state
                .pollers
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

    fn drop_sends(&self, enabled: bool) {
        self.state.lock().unwrap().drop_sends = enabled;
    }

    fn pause_recv(&self) {
        self.state.lock().unwrap().recv_paused = true;
    }

    fn resume_recv(&self) {
        let wake = {
            let mut state = self.state.lock().unwrap();
            state.recv_paused = false;
            state.recv_waker.take()
        };
        if let Some(wake) = wake {
            wake.wake();
        }
    }

    fn blocked_attempts(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .attempts
            .iter()
            .filter(|attempt| attempt.blocked)
            .count()
    }

    fn resent(&self, ciphertext: &[u8]) -> bool {
        self.state
            .lock()
            .unwrap()
            .attempts
            .iter()
            .any(|attempt| attempt.sent && attempt.ciphertext == ciphertext)
    }

    fn live_pollers(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .pollers
            .iter()
            .filter(|poller| poller.strong_count() > 0)
            .count()
    }
}

#[derive(Debug)]
struct GatePoller {
    socket: Arc<GateSocket>,
    inner: Pin<Box<dyn UdpPoller>>,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl UdpPoller for GatePoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let fresh = cx.waker().clone();
        let mut gate = this.socket.state.lock().unwrap();
        if let Some(error) = gate.poll_error {
            gate.injected_errors += 1;
            return Poll::Ready(Err(error.into()));
        }
        if gate.blocked {
            gate.pending_polls += 1;
            let old = this.waker.lock().unwrap().replace(fresh);
            drop(gate);
            drop(old);
            return Poll::Pending;
        }
        drop(gate);
        this.inner.as_mut().poll_writable(cx)
    }
}

impl AsyncUdpSocket for GateSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        let waker = Arc::new(Mutex::new(None));
        self.state
            .lock()
            .unwrap()
            .pollers
            .push(Arc::downgrade(&waker));
        Box::pin(GatePoller {
            inner: self.socket.clone().create_io_poller(),
            socket: self,
            waker,
        })
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        let (blocked, dropped, index) = {
            let mut state = self.state.lock().unwrap();
            if let Some(error) = state.send_error {
                state.injected_errors += 1;
                return Err(error.into());
            }
            let blocked = state.armed;
            if blocked {
                state.blocked = true;
            }
            let dropped = state.drop_sends;
            let index = state.attempts.len();
            state.attempts.push(Attempt {
                ciphertext: transmit.contents.to_vec(),
                blocked,
                dropped,
                sent: false,
            });
            (blocked, dropped, index)
        };
        if blocked {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if dropped {
            return Ok(());
        }
        let result = self.socket.try_send(transmit);
        if result.is_ok() {
            self.state.lock().unwrap().attempts[index].sent = true;
        }
        result
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let fresh = cx.waker().clone();
        let mut gate = self.state.lock().unwrap();
        if gate.recv_paused {
            let old = gate.recv_waker.replace(fresh);
            drop(gate);
            drop(old);
            return Poll::Pending;
        }
        drop(gate);
        self.socket.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    fn may_fragment(&self) -> bool {
        self.socket.may_fragment()
    }
}

async fn settle() {
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    sleep(Duration::from_millis(2)).await;
}

async fn until(mut ready: impl FnMut() -> bool) {
    timeout(Duration::from_secs(3), async {
        while !ready() {
            settle().await;
        }
    })
    .await
    .expect("runtime event did not arrive");
}

fn endpoints(
    clock: Arc<Clock>,
    single_probe: bool,
) -> (Endpoint, Endpoint, Arc<GateSocket>, Arc<GateSocket>) {
    configured_endpoints(clock, single_probe, false, false).0
}

type EndpointSet = (Endpoint, Endpoint, Arc<GateSocket>, Arc<GateSocket>);

fn configured_endpoints(
    clock: Arc<Clock>,
    single_probe: bool,
    tickets: bool,
    queue_pto: bool,
) -> (EndpointSet, crate::ServerConfig) {
    configured_endpoints_with_close_policy(clock, single_probe, tickets, queue_pto, false)
}

fn configured_endpoints_with_close_policy(
    clock: Arc<Clock>,
    single_probe: bool,
    tickets: bool,
    queue_pto: bool,
    discard_blocked_close: bool,
) -> (EndpointSet, crate::ServerConfig) {
    let factory = EndpointFactory::new();
    let mut transport = TransportConfig::default();
    transport
        .mtu_discovery_config(None)
        .ack_obligation_only(true)
        .pto_single_probe_with_gap(single_probe)
        .queue_pto_while_blocked(queue_pto)
        .discard_blocked_close(discard_blocked_close)
        .max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
    let transport = Arc::new(transport);
    let key = PrivateKeyDer::Pkcs8(factory.cert.signing_key.serialize_der().into());
    let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![factory.cert.cert.der().clone()], key)
        .unwrap();
    crypto.send_tls13_tickets = if tickets { 2 } else { 0 };
    crypto.max_early_data_size = if tickets { u32::MAX } else { 0 };
    let mut reject_crypto = crypto.clone();
    reject_crypto.max_early_data_size = 0;
    let mut reject_config = crate::ServerConfig::with_crypto(Arc::new(
        proto::crypto::rustls::QuicServerConfig::try_from(reject_crypto).unwrap(),
    ));
    reject_config.transport_config(transport.clone());
    let mut config = crate::ServerConfig::with_crypto(Arc::new(
        proto::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap(),
    ));
    config.transport_config(transport.clone());
    let mut roots = RootCertStore::empty();
    roots.add(factory.cert.cert.der().clone()).unwrap();
    let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    client_config.transport_config(transport);
    let runtime = Arc::new(TestRuntime(clock.clone(), "client"));
    let client_socket = GateSocket::bind();
    let server_socket = GateSocket::bind();
    let mut client = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        client_socket.clone(),
        runtime.clone(),
    )
    .unwrap();
    client.set_default_client_config(client_config);
    let server = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(config),
        server_socket.clone(),
        Arc::new(TestRuntime(clock, "server")),
    )
    .unwrap();
    (
        (client, server, client_socket, server_socket),
        reject_config,
    )
}

async fn with_clock<T>(clock: &Clock, future: impl Future<Output = T>) -> T {
    tokio::pin!(future);
    for _ in 0..100 {
        tokio::select! {
            result = &mut future => return result,
            _ = sleep(Duration::from_millis(5)) => clock.advance(Duration::from_millis(50)),
        }
    }
    panic!("operation did not finish within the controlled QUIC clock budget");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EarlyRelease {
    BeforeKeys,
    Accepted,
    Rejected,
}

struct EarlyObservation {
    accepted: bool,
    retried_early_ciphertext: bool,
    body: Vec<u8>,
    early_stream_rejected: bool,
    completed_early_writes: usize,
    new_one_rtt_packets: usize,
    new_zero_rtt_packets: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketLevel {
    Initial,
    Handshake,
    ZeroRtt,
    OneRtt,
}

fn packet_levels(ciphertext: &[u8]) -> Vec<PacketLevel> {
    let mut datagram = bytes::BytesMut::from(ciphertext);
    let mut result = Vec::new();
    // Long headers carry CID lengths; a short header is the final packet, so
    // its CID width is not needed to locate another packet boundary.
    let cid_parser = proto::FixedLengthConnectionIdParser::new(0);
    loop {
        let mut cursor = io::Cursor::new(datagram.clone());
        let header = proto::ProtectedHeader::decode(&mut cursor, &cid_parser, &[1], true).unwrap();
        result.push(match header {
            proto::ProtectedHeader::Initial(_) => PacketLevel::Initial,
            proto::ProtectedHeader::Long {
                ty: proto::LongType::Handshake,
                ..
            } => PacketLevel::Handshake,
            proto::ProtectedHeader::Long {
                ty: proto::LongType::ZeroRtt,
                ..
            } => PacketLevel::ZeroRtt,
            proto::ProtectedHeader::Short { .. } => PacketLevel::OneRtt,
            _ => panic!("unexpected packet kind in established resumption fixture"),
        });
        let original_len = datagram.len();
        let (packet, remaining) =
            proto::PartialDecode::new(datagram, &cid_parser, &[1], true).unwrap();
        assert_eq!(
            packet.len() + remaining.as_ref().map_or(0, bytes::BytesMut::len),
            original_len
        );
        match remaining {
            Some(next) => datagram = next,
            None => break,
        }
    }
    result
}

async fn early_write_block_case(single_probe: bool, release: EarlyRelease) -> EarlyObservation {
    let clock = Clock::new();
    let ((client_ep, server_ep, client_socket, _server_socket), reject_config) =
        configured_endpoints(clock.clone(), single_probe, true, single_probe);
    let (warm_client, warm_server) = with_clock(&clock, async {
        join!(
            client_ep
                .connect(server_ep.local_addr().unwrap(), "localhost")
                .unwrap(),
            async { server_ep.accept().await.unwrap().await }
        )
    })
    .await;
    let warm_client = warm_client.unwrap();
    let warm_server = warm_server.unwrap();
    let mut ready = warm_server.open_uni().await.unwrap();
    ready.write_all(b"ticket ready").await.unwrap();
    ready.finish().unwrap();
    let mut received = with_clock(&clock, warm_client.accept_uni()).await.unwrap();
    assert_eq!(
        with_clock(&clock, received.read_to_end(32)).await.unwrap(),
        b"ticket ready"
    );
    warm_client.close(0u32.into(), b"warmup done");
    warm_server.close(0u32.into(), b"warmup done");
    settle().await;
    clock.advance(Duration::from_secs(5));
    with_clock(&clock, async {
        join!(client_ep.wait_idle(), server_ep.wait_idle());
    })
    .await;
    drop((ready, received, warm_client, warm_server));
    eprintln!("0-RTT stage release={release:?} single_probe={single_probe}: warm ticket ready");
    if release == EarlyRelease::Rejected {
        server_ep.set_server_config(Some(reject_config));
    }
    client_socket.pause_recv();
    let (client, accepted) = client_ep
        .connect(server_ep.local_addr().unwrap(), "localhost")
        .unwrap()
        .into_0rtt()
        .unwrap_or_else(|_| panic!("real warmup ticket did not enable 0-RTT"));
    let incoming = timeout(Duration::from_secs(3), server_ep.accept())
        .await
        .unwrap()
        .unwrap();
    let (server, server_established) = incoming
        .accept()
        .unwrap()
        .into_0rtt()
        .unwrap_or_else(|_| panic!("server 0.5-RTT connection unavailable"));
    settle().await;
    client_socket.arm();
    let stream_frames = client.stats().frame_tx.stream;
    let (mut early_send, mut early_recv) = client.open_bi().await.unwrap();
    early_send.write_all(b"early request").await.unwrap();
    early_send.finish().unwrap();
    until(|| client_socket.state.lock().unwrap().blocked).await;
    assert_eq!(client.stats().frame_tx.stream, stream_frames + 1);
    let ciphertext = {
        let gate = client_socket.state.lock().unwrap();
        let blocked = gate
            .attempts
            .iter()
            .filter(|attempt| attempt.blocked)
            .collect::<Vec<_>>();
        assert_eq!(blocked.len(), 1);
        let bytes = &blocked[0].ciphertext;
        assert_eq!(
            bytes[0] & 0xb0,
            0x90,
            "must be an actual 0-RTT long-header packet"
        );
        assert_eq!(u32::from_be_bytes(bytes[1..5].try_into().unwrap()), 1);
        assert_eq!(packet_levels(bytes), vec![PacketLevel::ZeroRtt]);
        bytes.clone()
    };
    eprintln!("0-RTT stage release={release:?}: blocked actual early packet");
    if release == EarlyRelease::BeforeKeys {
        // No server flight has reached this client yet: the old cipher is
        // still valid and the peer must really receive these early bytes.
        client_socket.release();
        until(|| client_socket.resent(&ciphertext)).await;
    }
    client_socket.resume_recv();
    eprintln!("0-RTT stage release={release:?}: waiting client decision");
    let accepted = with_clock(&clock, accepted).await;
    eprintln!(
        "0-RTT stage release={release:?}: client decision={accepted} client_error={:?} server_error={:?}",
        client.close_reason(),
        server.close_reason()
    );
    assert!(
        client.close_reason().is_none() && server.close_reason().is_none(),
        "decision must come from a live completed TLS handshake"
    );
    assert_eq!(accepted, release != EarlyRelease::Rejected);
    let after_keys_attempt = client_socket.state.lock().unwrap().attempts.len();
    let mut early_stream_rejected = false;
    if !accepted {
        early_stream_rejected = matches!(
            early_send.stopped().await,
            Err(crate::StoppedError::ZeroRttRejected)
        );
        assert!(matches!(
            early_recv.read(&mut [0; 1]).await,
            Err(crate::ReadError::ZeroRttRejected)
        ));
    }
    client_socket.release();
    let server_early_result = with_clock(&clock, server_established).await;
    eprintln!(
        "0-RTT stage release={release:?}: server complete early_result={server_early_result} client_error={:?} server_error={:?}",
        client.close_reason(),
        server.close_reason()
    );
    assert!(client.close_reason().is_none() && server.close_reason().is_none());
    let body = if accepted {
        let (mut reply, mut request) = with_clock(&clock, server.accept_bi()).await.unwrap();
        assert_eq!(
            with_clock(&clock, request.read_to_end(64)).await.unwrap(),
            b"early request"
        );
        reply.write_all(b"early response").await.unwrap();
        reply.finish().unwrap();
        with_clock(&clock, early_recv.read_to_end(64))
            .await
            .unwrap()
    } else {
        drop((early_send, early_recv));
        let (mut send, mut recv) = client.open_bi().await.unwrap();
        send.write_all(b"fresh request").await.unwrap();
        send.finish().unwrap();
        let (mut reply, mut request) = with_clock(&clock, server.accept_bi()).await.unwrap();
        assert_eq!(
            with_clock(&clock, request.read_to_end(64)).await.unwrap(),
            b"fresh request"
        );
        reply.write_all(b"fresh response").await.unwrap();
        reply.finish().unwrap();
        with_clock(&clock, recv.read_to_end(64)).await.unwrap()
    };
    let retried_early_ciphertext = client_socket.resent(&ciphertext);
    let (completed_early_writes, new_one_rtt_packets, new_zero_rtt_packets) = {
        let gate = client_socket.state.lock().unwrap();
        let completed = gate
            .attempts
            .iter()
            .filter(|attempt| attempt.sent && attempt.ciphertext == ciphertext)
            .count();
        let mut one_rtt = 0;
        let mut zero_rtt = 0;
        for attempt in &gate.attempts[after_keys_attempt..] {
            if !attempt.sent || attempt.ciphertext == ciphertext {
                continue;
            }
            for level in packet_levels(&attempt.ciphertext) {
                one_rtt += usize::from(level == PacketLevel::OneRtt);
                zero_rtt += usize::from(level == PacketLevel::ZeroRtt);
            }
        }
        (completed, one_rtt, zero_rtt)
    };
    eprintln!(
        "0-RTT packetization release={release:?} same_cipher_completions={completed_early_writes} new_1rtt_packets={new_one_rtt_packets} new_0rtt_packets={new_zero_rtt_packets}"
    );
    eprintln!(
        "0-RTT blocked release={release:?} single_probe={single_probe} accepted={accepted} old_cipher_retried={retried_early_ciphertext} early_stream_rejected={early_stream_rejected} response_bytes={}",
        body.len()
    );
    client_ep.close(0u32.into(), b"done");
    server_ep.close(0u32.into(), b"done");
    settle().await;
    clock.advance(Duration::from_secs(60));
    with_clock(&clock, async {
        join!(client_ep.wait_idle(), server_ep.wait_idle());
    })
    .await;
    EarlyObservation {
        accepted,
        retried_early_ciphertext,
        body,
        early_stream_rejected,
        completed_early_writes,
        new_one_rtt_packets,
        new_zero_rtt_packets,
    }
}

#[tokio::test]
async fn zero_rtt_write_block_before_keys_preserves_valid_ciphertext_retry() {
    for single_probe in [false, true] {
        let observed = early_write_block_case(single_probe, EarlyRelease::BeforeKeys).await;
        assert!(observed.accepted && observed.retried_early_ciphertext);
        assert_eq!(observed.body, b"early response");
        assert_eq!(observed.completed_early_writes, 1);
        assert_eq!(observed.new_zero_rtt_packets, 0);
    }
}

#[tokio::test]
async fn zero_rtt_write_block_accepted_completes_old_write_without_new_early_packetization() {
    for single_probe in [false, true] {
        let observed = early_write_block_case(single_probe, EarlyRelease::Accepted).await;
        assert!(observed.accepted);
        assert_eq!(observed.body, b"early response");
        assert!(observed.retried_early_ciphertext);
        assert_eq!(observed.completed_early_writes, 1);
        assert_eq!(observed.new_zero_rtt_packets, 0);
        assert!(observed.new_one_rtt_packets > 0);
    }
}

#[tokio::test]
async fn zero_rtt_write_block_rejected_stream_recovers_without_new_early_packetization() {
    for single_probe in [false, true] {
        let observed = early_write_block_case(single_probe, EarlyRelease::Rejected).await;
        assert!(!observed.accepted && observed.early_stream_rejected);
        assert_eq!(observed.body, b"fresh response");
        assert!(observed.retried_early_ciphertext);
        assert_eq!(observed.completed_early_writes, 1);
        assert_eq!(observed.new_zero_rtt_packets, 0);
        assert!(observed.new_one_rtt_packets > 0);
    }
}

struct RuntimeCase {
    clock: Arc<Clock>,
    client_ep: Endpoint,
    server_ep: Endpoint,
    client: crate::Connection,
    server: crate::Connection,
    client_socket: Arc<GateSocket>,
    server_socket: Arc<GateSocket>,
}

impl RuntimeCase {
    async fn new(single_probe: bool) -> Self {
        let clock = Clock::new();
        let (client_ep, server_ep, client_socket, server_socket) =
            endpoints(clock.clone(), single_probe);
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
        clock.advance(Duration::from_millis(50));
        settle().await;
        Self {
            clock,
            client_ep,
            server_ep,
            client,
            server,
            client_socket,
            server_socket,
        }
    }

    async fn blocked_tail(&self) -> (SendStream, RecvStream, Vec<u8>) {
        let (mut upload, response) = self.client.open_bi().await.unwrap();
        upload.write_all(b"prefix").await.unwrap();
        let (reply, mut request) = timeout(Duration::from_secs(3), self.server.accept_bi())
            .await
            .unwrap()
            .unwrap();
        let mut prefix = [0; 6];
        request.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix, b"prefix");
        self.clock.advance(Duration::from_millis(50));
        settle().await;
        self.client_socket.arm();
        let stream_frames = self.client.stats().frame_tx.stream;
        upload.write_all(b"withheld tail").await.unwrap();
        until(|| self.client_socket.state.lock().unwrap().blocked).await;
        assert_eq!(self.client.stats().frame_tx.stream, stream_frames + 1);
        let ciphertext = {
            let state = self.client_socket.state.lock().unwrap();
            let blocked = state
                .attempts
                .iter()
                .filter(|attempt| attempt.blocked)
                .collect::<Vec<_>>();
            assert_eq!(blocked.len(), 1);
            assert_eq!(blocked[0].ciphertext[0] & 0x80, 0);
            blocked[0].ciphertext.clone()
        };
        drop((reply, response));
        (upload, request, ciphertext)
    }
}

#[tokio::test]
async fn pto_write_block_local_close_must_abandon_buffered_application_packet() {
    for single_probe in [false, true] {
        let case = RuntimeCase::new(single_probe).await;
        let (_upload, _request, ciphertext) = case.blocked_tail().await;
        case.client.close(41u32.into(), b"local close");
        assert!(matches!(
            timeout(Duration::from_secs(3), case.client.closed())
                .await
                .unwrap(),
            crate::ConnectionError::LocallyClosed
        ));
        case.client_socket.release();
        settle().await;
        eprintln!(
            "local close: stale_ciphertext_resent={}",
            case.client_socket.resent(&ciphertext)
        );
        assert!(
            !case.client_socket.resent(&ciphertext),
            "local close must abandon already buffered application data"
        );
    }
}

#[tokio::test]
async fn pto_write_block_peer_close_must_abandon_buffered_application_packet() {
    for single_probe in [false, true] {
        let case = RuntimeCase::new(single_probe).await;
        let (_upload, _request, ciphertext) = case.blocked_tail().await;
        case.server.close(42u32.into(), b"peer close");
        assert!(
            matches!(timeout(Duration::from_secs(3), case.client.closed()).await.unwrap(), crate::ConnectionError::ApplicationClosed(close) if close.error_code.into_inner() == 42)
        );
        case.client_socket.release();
        settle().await;
        eprintln!(
            "peer close: stale_ciphertext_resent={}",
            case.client_socket.resent(&ciphertext)
        );
        assert!(
            !case.client_socket.resent(&ciphertext),
            "draining connection must not send its old application packet"
        );
    }
}

#[tokio::test]
async fn pto_write_block_fresh_close_packet_retries_while_still_closing() {
    for single_probe in [false, true] {
        let case = RuntimeCase::new(single_probe).await;
        case.client_socket.arm();
        case.client.close(41u32.into(), b"local close");
        until(|| case.client_socket.state.lock().unwrap().blocked).await;
        assert!(matches!(
            case.client.close_reason(),
            Some(crate::ConnectionError::LocallyClosed)
        ));
        let ciphertext = case
            .client_socket
            .state
            .lock()
            .unwrap()
            .attempts
            .iter()
            .find(|attempt| attempt.blocked)
            .unwrap()
            .ciphertext
            .clone();
        case.client.close(41u32.into(), b"local close repeated");
        case.client_socket.release();
        let reason = timeout(Duration::from_secs(3), case.server.closed())
            .await
            .unwrap();
        assert!(
            matches!(reason, crate::ConnectionError::ApplicationClosed(close) if close.error_code.into_inner() == 41)
        );
        assert!(
            case.client_socket.resent(&ciphertext),
            "a new Close buffered in Closing remains retryable"
        );
    }
}

#[tokio::test]
async fn pto_write_block_draining_to_drained_discards_blocked_close_response() {
    for single_probe in [false, true] {
        let case = RuntimeCase::new(single_probe).await;
        case.client_socket.arm();
        case.server.close(42u32.into(), b"peer close");
        assert!(
            matches!(timeout(Duration::from_secs(3), case.client.closed()).await.unwrap(), crate::ConnectionError::ApplicationClosed(close) if close.error_code.into_inner() == 42)
        );
        until(|| case.client_socket.state.lock().unwrap().blocked).await;
        let ciphertext = case
            .client_socket
            .state
            .lock()
            .unwrap()
            .attempts
            .iter()
            .find(|attempt| attempt.blocked)
            .unwrap()
            .ciphertext
            .clone();
        case.clock.advance(Duration::from_secs(5));
        timeout(Duration::from_secs(3), async {
            join!(case.client_ep.wait_idle(), case.server_ep.wait_idle());
        })
        .await
        .unwrap();
        case.client_socket.release();
        settle().await;
        assert!(
            !case.client_socket.resent(&ciphertext),
            "drained connection cannot retry its earlier close response"
        );
    }
}

#[tokio::test]
async fn pto_write_block_closing_to_draining_must_abandon_old_close_packet() {
    for single_probe in [false, true] {
        let case = RuntimeCase::new(single_probe).await;
        case.client_socket.arm();
        case.client.close(41u32.into(), b"local close");
        until(|| case.client_socket.state.lock().unwrap().blocked).await;
        assert!(matches!(
            case.client.close_reason(),
            Some(crate::ConnectionError::LocallyClosed)
        ));
        let ciphertext = case
            .client_socket
            .state
            .lock()
            .unwrap()
            .attempts
            .iter()
            .find(|attempt| attempt.blocked)
            .unwrap()
            .ciphertext
            .clone();
        case.server.close(42u32.into(), b"peer close");
        until(|| case.client.stats().frame_rx.connection_close > 0).await;
        assert!(matches!(
            case.client.close_reason(),
            Some(crate::ConnectionError::LocallyClosed)
        ));
        case.client_socket.release();
        settle().await;
        eprintln!(
            "Closing->Draining single_probe={single_probe} old_close_resent={}",
            case.client_socket.resent(&ciphertext)
        );
        assert!(
            !case.client_socket.resent(&ciphertext),
            "entering Draining invalidates the earlier Closing packet"
        );
    }
}

#[derive(Debug, Clone, Copy)]
enum Terminal {
    Local,
    Peer,
    Idle,
}

#[derive(Debug, Clone, Copy)]
enum TimerPhase {
    Idle,
    Closing,
    Draining,
}

#[derive(Debug, Clone, Copy)]
enum ReleaseOrder {
    Before,
    Processed,
    SamePoll,
}

async fn advance_blocked_to_idle_timer(case: &RuntimeCase) -> Instant {
    let expected = case.clock.now() + Duration::from_secs(10);
    case.client_socket.pause_recv();
    for _ in 0..32 {
        let next = case.clock.deadline("client");
        assert!(next >= case.clock.now());
        if next >= expected {
            assert_eq!(next, expected, "observe the actual scheduled idle deadline");
            return next;
        }
        case.clock.advance(next - case.clock.now());
        settle().await;
        assert!(case.client.close_reason().is_none());
    }
    panic!("fixture did not reach its real idle timer");
}

#[tokio::test]
async fn timer_write_order_observes_release_before_after_and_same_poll_as_expiry() {
    for phase in [TimerPhase::Idle, TimerPhase::Closing, TimerPhase::Draining] {
        for order in [
            ReleaseOrder::Before,
            ReleaseOrder::Processed,
            ReleaseOrder::SamePoll,
        ] {
            let case = RuntimeCase::new(true).await;
            let mut held_streams = None;
            let (ciphertext, deadline) = match phase {
                TimerPhase::Idle => {
                    let (upload, request, bytes) = case.blocked_tail().await;
                    held_streams = Some((upload, request));
                    let deadline = advance_blocked_to_idle_timer(&case).await;
                    (bytes, deadline)
                }
                TimerPhase::Closing | TimerPhase::Draining => {
                    case.client_socket.arm();
                    if matches!(phase, TimerPhase::Closing) {
                        case.client.close(41u32.into(), b"timer control");
                    } else {
                        case.server.close(42u32.into(), b"timer control");
                        assert!(matches!(
                            timeout(Duration::from_secs(3), case.client.closed())
                                .await
                                .unwrap(),
                            crate::ConnectionError::ApplicationClosed(_)
                        ));
                    }
                    until(|| case.client_socket.state.lock().unwrap().blocked).await;
                    let bytes = case
                        .client_socket
                        .state
                        .lock()
                        .unwrap()
                        .attempts
                        .iter()
                        .find(|attempt| attempt.blocked)
                        .unwrap()
                        .ciphertext
                        .clone();
                    case.client_socket.pause_recv();
                    (bytes, case.clock.deadline("client"))
                }
            };
            assert!(deadline > case.clock.now());
            match order {
                ReleaseOrder::Before => {
                    case.clock
                        .advance(deadline - case.clock.now() - Duration::from_nanos(1));
                    case.client_socket.release();
                    settle().await;
                    assert!(case.client_socket.resent(&ciphertext));
                }
                ReleaseOrder::Processed => {
                    case.clock.advance(deadline - case.clock.now());
                    if matches!(phase, TimerPhase::Idle) {
                        assert!(matches!(
                            timeout(Duration::from_secs(3), case.client.closed())
                                .await
                                .unwrap(),
                            crate::ConnectionError::TimedOut
                        ));
                    }
                    timeout(Duration::from_secs(3), case.client_ep.wait_idle())
                        .await
                        .unwrap();
                    case.client_socket.release();
                    settle().await;
                    assert!(!case.client_socket.resent(&ciphertext));
                }
                ReleaseOrder::SamePoll => {
                    // No await/yield between making the deadline due and the
                    // socket writable: driver ordering decides this case.
                    case.clock.advance(deadline - case.clock.now());
                    case.client_socket.release();
                    settle().await;
                }
            }
            let completed = case.client_socket.resent(&ciphertext);
            if !matches!(order, ReleaseOrder::Before) && matches!(phase, TimerPhase::Idle) {
                assert!(matches!(
                    timeout(Duration::from_secs(3), case.client.closed())
                        .await
                        .unwrap(),
                    crate::ConnectionError::TimedOut
                ));
            }
            eprintln!(
                "timer/write phase={phase:?} order={order:?} held_cipher_completed={completed} close_reason={:?}",
                case.client.close_reason()
            );
            // Close and drain both endpoints independently of the observed send.
            case.client_socket.resume_recv();
            case.client_ep.close(0u32.into(), b"cleanup");
            case.server_ep.close(0u32.into(), b"cleanup");
            settle().await;
            case.clock.advance(Duration::from_secs(60));
            with_clock(&case.clock, async {
                join!(case.client_ep.wait_idle(), case.server_ep.wait_idle());
            })
            .await;
            drop(held_streams);
        }
    }
}

#[tokio::test]
async fn timer_write_order_authenticated_peer_event_refreshes_idle_before_old_deadline() {
    let case = RuntimeCase::new(true).await;
    let (_upload, mut request, ciphertext) = case.blocked_tail().await;
    let old_deadline = case.clock.now() + Duration::from_secs(10);
    case.client_socket.pause_recv();
    case.clock.advance(Duration::from_secs(1));
    settle().await;
    case.server
        .send_datagram(Bytes::from_static(b"refresh idle"))
        .unwrap();
    settle().await;
    case.client_socket.resume_recv();
    assert_eq!(
        timeout(Duration::from_secs(3), case.client.read_datagram())
            .await
            .unwrap()
            .unwrap(),
        b"refresh idle"[..]
    );
    case.client_socket.pause_recv();
    // Receiving the authenticated packet has already run before the old
    // deadline. Do not conflate this with arrival in the same driver poll.
    case.clock.advance(old_deadline - case.clock.now());
    case.client_socket.release();
    settle().await;
    assert!(case.client.close_reason().is_none());
    assert!(case.client_socket.resent(&ciphertext));
    let mut tail = [0; 13];
    timeout(Duration::from_secs(3), request.read_exact(&mut tail))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&tail, b"withheld tail");
    eprintln!(
        "timer/write authenticated refresh: old_deadline_passed=true still_open=true held_cipher_completed=true"
    );
    case.client_socket.resume_recv();
    case.client_ep.close(0u32.into(), b"cleanup");
    case.server_ep.close(0u32.into(), b"cleanup");
    settle().await;
    case.clock.advance(Duration::from_secs(60));
    with_clock(&case.clock, async {
        join!(case.client_ep.wait_idle(), case.server_ep.wait_idle());
    })
    .await;
}

#[tokio::test]
async fn pto_write_block_permanent_block_does_not_stall_terminal_cleanup() {
    for single_probe in [false, true] {
        for terminal in [Terminal::Local, Terminal::Peer, Terminal::Idle] {
            let case = RuntimeCase::new(single_probe).await;
            let (upload, request, _) = case.blocked_tail().await;
            match terminal {
                Terminal::Local => case.client.close(41u32.into(), b"local close"),
                Terminal::Peer => case.server.close(42u32.into(), b"peer close"),
                Terminal::Idle => case.clock.advance(Duration::from_secs(11)),
            }
            let reason = timeout(Duration::from_secs(3), case.client.closed())
                .await
                .unwrap();
            match terminal {
                Terminal::Local => assert!(matches!(reason, crate::ConnectionError::LocallyClosed)),
                Terminal::Peer => assert!(
                    matches!(reason, crate::ConnectionError::ApplicationClosed(close) if close.error_code.into_inner() == 42)
                ),
                Terminal::Idle => assert!(matches!(reason, crate::ConnectionError::TimedOut)),
            }
            case.server_ep.close(0u32.into(), b"cleanup");
            settle().await;
            case.clock.advance(Duration::from_secs(5));
            timeout(Duration::from_secs(3), async {
                join!(case.client_ep.wait_idle(), case.server_ep.wait_idle());
            })
            .await
            .expect("blocked socket must not prevent protocol drain");
            let blocked_attempts = case.client_socket.blocked_attempts();
            assert!(blocked_attempts >= 1);
            for _ in 0..3 {
                case.clock.advance(Duration::from_secs(1));
                settle().await;
                assert_eq!(
                    case.client_socket.blocked_attempts(),
                    blocked_attempts,
                    "terminal endpoint must not spin on WouldBlock"
                );
            }
            let RuntimeCase {
                clock,
                client_ep,
                server_ep,
                client,
                server,
                client_socket,
                server_socket,
            } = case;
            eprintln!(
                "permanent {terminal:?}: closed and idle; blocked_attempts={blocked_attempts} retained_handle_pollers={}",
                client_socket.live_pollers()
            );
            drop((upload, request, client, server, client_ep, server_ep));
            until(|| clock.tasks.load(Ordering::SeqCst) == 0).await;
            assert_eq!(client_socket.live_pollers(), 0);
            assert_eq!(server_socket.live_pollers(), 0);
            assert_eq!(
                clock
                    .state
                    .lock()
                    .unwrap()
                    .timers
                    .iter()
                    .filter(|timer| timer.strong_count() > 0)
                    .count(),
                0
            );
        }
    }
}

#[tokio::test]
async fn pto_write_block_keeps_one_ciphertext_until_writable_and_recovers_response() {
    for single_probe in [false, true] {
        let clock = Clock::new();
        let (client_ep, server_ep, client_socket, server_socket) =
            endpoints(clock.clone(), single_probe);
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
        clock.advance(Duration::from_millis(50));
        settle().await;
        let (mut upload, mut response) = client.open_bi().await.unwrap();
        upload.write_all(b"request").await.unwrap();
        let (mut reply, mut request) = timeout(Duration::from_secs(3), server.accept_bi())
            .await
            .unwrap()
            .unwrap();
        let mut body = [0; 7];
        request.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"request");
        server_socket.drop_sends(true);
        upload.reset(268u32.into()).unwrap();
        let mut tail = [0; 1];
        assert!(
            matches!(timeout(Duration::from_secs(3), request.read(&mut tail)).await.unwrap(), Err(crate::ReadError::Reset(code)) if code.into_inner() == 268)
        );
        until(|| client.stats().frame_tx.reset_stream == 1).await;
        client_socket.arm();
        clock.advance(Duration::from_millis(100));
        until(|| client_socket.state.lock().unwrap().blocked).await;
        let generated = client.stats().frame_tx.reset_stream;
        assert!(generated >= 2);
        let blocked_ciphertext = {
            let state = client_socket.state.lock().unwrap();
            let attempts = state
                .attempts
                .iter()
                .filter(|attempt| attempt.blocked)
                .collect::<Vec<_>>();
            assert_eq!(attempts.len(), 1);
            assert_eq!(
                attempts[0].ciphertext[0] & 0x80,
                0,
                "blocked packet must be 1-RTT"
            );
            attempts[0].ciphertext.clone()
        };
        for elapsed in [100, 200, 400, 800] {
            clock.advance(Duration::from_millis(elapsed));
            settle().await;
            assert_eq!(
                client.stats().frame_tx.reset_stream,
                generated,
                "one runtime buffer prevents more proto packetization"
            );
            assert_eq!(
                client_socket
                    .state
                    .lock()
                    .unwrap()
                    .attempts
                    .iter()
                    .filter(|attempt| attempt.blocked)
                    .count(),
                1
            );
        }
        assert!(
            server_socket
                .state
                .lock()
                .unwrap()
                .attempts
                .iter()
                .any(|attempt| attempt.dropped)
        );
        server_socket.drop_sends(false);
        client_socket.release();
        until(|| {
            client_socket
                .state
                .lock()
                .unwrap()
                .attempts
                .iter()
                .any(|attempt| attempt.sent && attempt.ciphertext == blocked_ciphertext)
        })
        .await;
        reply.write_all(b"response survives").await.unwrap();
        reply.finish().unwrap();
        assert_eq!(
            timeout(Duration::from_secs(3), response.read_to_end(64))
                .await
                .unwrap()
                .unwrap(),
            b"response survives"
        );
        eprintln!(
            "WouldBlock single_probe={single_probe}: generated_while_blocked={generated}, held_bytes={}, reset_frames_after_release={}",
            blocked_ciphertext.len(),
            client.stats().frame_tx.reset_stream
        );
        client_ep.close(0u32.into(), b"done");
        server_ep.close(0u32.into(), b"done");
        settle().await;
        clock.advance(Duration::from_secs(5));
        timeout(Duration::from_secs(3), async {
            join!(client_ep.wait_idle(), server_ep.wait_idle());
        })
        .await
        .unwrap();
        assert_eq!(
            client_socket
                .state
                .lock()
                .unwrap()
                .pollers
                .iter()
                .filter_map(Weak::upgrade)
                .filter(|waiter| waiter.lock().unwrap().is_some())
                .count(),
            0
        );
    }
}
