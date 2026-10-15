use super::*;
use crate::connection::PtoTimingSnapshot;
use crate::packet::SpaceId;
use crate::shared::ConnectionEventInner;

struct TimingCase {
    pair: Pair,
    client: ConnectionHandle,
    server: ConnectionHandle,
}

fn transmit(connection: &mut Connection, now: Instant) -> Vec<(Option<EcnCodepoint>, BytesMut)> {
    let mut result = Vec::new();
    let mut buffer = Vec::new();
    while let Some(sent) = connection.poll_transmit(now, 1, &mut buffer) {
        assert!(sent.segment_size.is_none());
        result.push((sent.ecn, BytesMut::from(&buffer[..sent.size])));
        buffer.clear();
    }
    result
}

fn deliver(
    endpoint: &mut TestEndpoint,
    remote: SocketAddr,
    expected: ConnectionHandle,
    at: Instant,
    packets: Vec<(Option<EcnCodepoint>, BytesMut)>,
) -> Vec<(u64, Vec<Frame>)> {
    packets
        .into_iter()
        .map(|(ecn, bytes)| {
            let Some(DatagramEvent::ConnectionEvent(handle, event)) =
                endpoint.handle(at, remote, None, ecn, bytes, &mut Vec::new())
            else {
                panic!("expected established encrypted peer packet");
            };
            assert_eq!(handle, expected);
            let conn = endpoint.connections.get_mut(&handle).unwrap();
            let (number, payload) = conn.decode_packet_with_number(&event).unwrap();
            let frames = frame::Iter::new(payload.into())
                .unwrap()
                .map(Result::unwrap)
                .filter(|frame| !matches!(frame, Frame::Padding))
                .collect();
            conn.handle_event(event);
            (number.unwrap(), frames)
        })
        .collect()
}

impl TimingCase {
    fn new(latency: Duration) -> Self {
        Self::configured(latency, false)
    }

    fn configured(latency: Duration, timing: bool) -> Self {
        Self::with_ack_delay(latency, timing, None)
    }

    fn with_ack_delay(latency: Duration, timing: bool, ack_delay: Option<Duration>) -> Self {
        let mut server = server_config();
        let mut transport = TransportConfig::default();
        transport
            .deterministic_packet_numbers(true)
            .mtu_discovery_config(None)
            .enable_ecn(false)
            .send_min_ack_delay_transport_parameter(ack_delay.is_some())
            .ack_obligation_only(true);
        server.transport_config(Arc::new(transport));
        let mut client = client_config_with_deterministic_pns();
        Arc::get_mut(&mut client.transport)
            .unwrap()
            .mtu_discovery_config(None)
            .enable_ecn(false)
            .ack_obligation_only(true)
            .pto_single_probe_with_gap(true);
        Arc::get_mut(&mut client.transport)
            .unwrap()
            .chrome_pto_timing(timing);
        if let Some(delay) = ack_delay {
            let mut frequency = AckFrequencyConfig::default();
            frequency.max_ack_delay(Some(delay));
            Arc::get_mut(&mut client.transport)
                .unwrap()
                .ack_frequency_config(Some(frequency));
        }
        let mut pair = Pair::new(Default::default(), server);
        pair.latency = latency;
        let (client, server) = pair.connect_with(client);
        if let Some(delay) = ack_delay {
            assert!(pair.server_conn_mut(server).stats().frame_rx.ack_frequency > 0);
            assert_eq!(
                pair.client_conn_mut(client)
                    .pto_timing_for_test()
                    .max_ack_delay,
                delay
            );
        }
        Self {
            pair,
            client,
            server,
        }
    }

    fn snapshot(&mut self) -> PtoTimingSnapshot {
        self.pair.client_conn_mut(self.client).pto_timing_for_test()
    }

    fn ping_packet(&mut self) -> Vec<(Option<EcnCodepoint>, BytesMut)> {
        let now = self.pair.time;
        self.pair.client_conn_mut(self.client).ping();
        let packets = transmit(self.pair.client_conn_mut(self.client), now);
        assert_eq!(packets.len(), 1);
        packets
    }

    fn send_unacknowledged_ping(&mut self) -> Instant {
        let sent = self.pair.time;
        let packets = self.ping_packet();
        let remote = self.pair.client.addr;
        let received = deliver(&mut self.pair.server, remote, self.server, sent, packets);
        assert!(
            received[0]
                .1
                .iter()
                .any(|frame| matches!(frame, Frame::Ping))
        );
        sent
    }

    fn rtt_sample(&mut self, one_way: Duration) {
        let mut packets = self.ping_packet();
        packets.extend(self.ping_packet());
        self.pair.time += one_way;
        let remote = self.pair.client.addr;
        let at = self.pair.time;
        let received = deliver(&mut self.pair.server, remote, self.server, at, packets);
        assert_eq!(received.len(), 2);
        let acks = transmit(self.pair.server_conn_mut(self.server), at);
        assert_eq!(acks.len(), 1);
        self.pair.time += one_way;
        let at = self.pair.time;
        let remote = self.pair.server.addr;
        let received = deliver(&mut self.pair.client, remote, self.client, at, acks);
        assert!(
            received[0]
                .1
                .iter()
                .any(|frame| matches!(frame, Frame::Ack(ack) if ack.delay == 0))
        );
    }
}

fn legacy_deadline(state: &PtoTimingSnapshot) -> Instant {
    let base =
        state.smoothed + (4 * state.variance).max(Duration::from_millis(1)) + state.max_ack_delay;
    state.last_ack_eliciting.unwrap() + base * 2u32.pow(state.backoff.min(16))
}

// This comparison uses actual local Quinn estimator inputs, not inferred
// Chrome RTT. Only the local formula inputs are truncated to whole microseconds.
fn chrome_source_deadline(state: &PtoTimingSnapshot, now: Instant) -> Instant {
    assert!(state.sampled);
    let quantize =
        |duration: Duration| Duration::from_micros(duration.as_micros().try_into().unwrap());
    let srtt = quantize(state.smoothed);
    let base = srtt
        + (2 * quantize(state.variance)).max(Duration::from_millis(1))
        + quantize(state.max_ack_delay);
    let half = Duration::from_micros(srtt.as_micros().div_ceil(2).try_into().unwrap());
    if state.backoff == 0 {
        now.max(state.first_in_flight.unwrap() + base)
            .max(state.last_ack_eliciting.unwrap() + srtt + half)
    } else {
        now.max(state.last_ack_eliciting.unwrap() + base * 2u32.pow(state.backoff.min(16)))
    }
}

fn chrome_first_flight_expectation(spread: u64) -> (Instant, Instant) {
    let mut case = TimingCase::configured(Duration::from_millis(20), true);
    let first = case.send_unacknowledged_ping();
    case.pair.time += Duration::from_millis(spread);
    let last = case.send_unacknowledged_ping();
    let state = case.snapshot();
    let actual = state.deadline.unwrap();
    let expected = chrome_source_deadline(&state, case.pair.time);
    eprintln!(
        "Chrome timing expectation S={:?} V={:?} A={:?} first=0 last={:?} k={} actual={:?} expected={:?}",
        state.smoothed,
        state.variance,
        state.max_ack_delay,
        last - first,
        state.backoff,
        actual - first,
        expected - first
    );
    (actual, expected)
}

#[test]
fn pto_timing_chrome_first_flight_left_edge_expectation() {
    let (actual, expected) = chrome_first_flight_expectation(5);
    assert_eq!(actual, expected);
}

#[test]
fn pto_timing_chrome_first_flight_right_edge_expectation() {
    let (actual, expected) = chrome_first_flight_expectation(50);
    assert_eq!(actual, expected);
}

#[test]
fn pto_timing_chrome_later_backoff_expectation() {
    let mut case = TimingCase::configured(Duration::from_millis(20), true);
    case.send_unacknowledged_ping();
    let deadline = case.snapshot().deadline.unwrap();
    case.pair.time = deadline;
    case.pair
        .client_conn_mut(case.client)
        .handle_timeout(deadline);
    let probe = transmit(case.pair.client_conn_mut(case.client), deadline);
    assert_eq!(probe.len(), 1);
    let state = case.snapshot();
    assert_eq!(state.backoff, 1);
    let expected = chrome_source_deadline(&state, deadline);
    eprintln!(
        "Chrome later expectation S={:?} V={:?} A={:?} k={} actual_interval={:?} expected_interval={:?}",
        state.smoothed,
        state.variance,
        state.max_ack_delay,
        state.backoff,
        state.deadline.unwrap() - deadline,
        expected - deadline
    );
    assert_eq!(state.deadline, Some(expected));
}

fn awaiting_confirmation(
    timing: bool,
    resumed: bool,
    acknowledge_handshake: bool,
) -> (
    Pair,
    ConnectionHandle,
    ConnectionHandle,
    Vec<ConnectionEvent>,
) {
    let mut pair = Pair::default_with_deterministic_pns();
    pair.latency = Duration::from_millis(20);
    let mut config = client_config_with_deterministic_pns();
    Arc::get_mut(&mut config.transport)
        .unwrap()
        .mtu_discovery_config(None)
        .pto_single_probe_with_gap(true)
        .chrome_pto_timing(timing);
    if resumed {
        let (warm, _) = pair.connect_with(config.clone());
        let now = pair.time;
        pair.client_conn_mut(warm)
            .close(now, VarInt(0), Bytes::new());
        pair.drive();
        pair.client
            .addr
            .set_port(CLIENT_PORTS.lock().unwrap().next().unwrap());
    }
    let client = pair.begin_connect(config);
    if resumed {
        assert!(pair.client_conn_mut(client).has_0rtt());
        let stream = pair.client_streams(client).open(Dir::Bi).unwrap();
        pair.client_send(client, stream).write(b"early").unwrap();
    }
    pair.drive_client();
    pair.time += Duration::from_millis(20);
    pair.drive_server();
    let server = pair.server.assert_accept();
    pair.time += Duration::from_millis(20);
    pair.drive_client();
    let before = pair.client_conn_mut(client).pto_timing_for_test();
    assert!(!before.handshaking && before.has_data_keys && before.has_handshake_keys);
    assert!(before.handshake_in_flight);
    if !resumed {
        assert!(!before.data_acknowledged);
    }
    assert!(!before.confirmed);
    let mut held = Vec::new();
    let mut handshake_pns = Vec::new();
    pair.time += Duration::from_millis(20);
    while let Some((at, ecn, bytes)) = pair.server.inbound.pop_front() {
        let Some(DatagramEvent::ConnectionEvent(handle, mut event)) =
            pair.server
                .handle(at, pair.client.addr, None, ecn, bytes, &mut Vec::new())
        else {
            panic!("real Finished must route to server");
        };
        assert_eq!(handle, server);
        let ConnectionEventInner::Datagram(ref mut datagram) = event.0 else {
            unreachable!()
        };
        let space = datagram.first_decode.space().unwrap();
        let remaining = datagram.remaining.take();
        if let Some(remaining) = remaining {
            pair.server.inbound.push_front((at, ecn, remaining));
        }
        if space == SpaceId::Initial {
            pair.server_conn_mut(server).handle_event(event);
            continue;
        }
        if space == SpaceId::Data {
            held.push(event);
            continue;
        }
        assert_eq!(space, SpaceId::Handshake);
        let (pn, payload) = pair
            .server_conn_mut(server)
            .decode_packet_with_number(&event)
            .unwrap();
        assert!(
            frame::Iter::new(payload.into())
                .unwrap()
                .any(|frame| matches!(frame.unwrap(), Frame::Crypto(_)))
        );
        handshake_pns.push(pn.unwrap()..=pn.unwrap());
        held.push(event);
    }
    assert!(!handshake_pns.is_empty());
    // A controlled peer acknowledges the authenticated Finished packet before
    // dispatching its TLS message. Its real Handshake keys remain available.
    if acknowledge_handshake {
        let now = pair.time;
        pair.server_conn_mut(server)
            .queue_ack_in_space_for_pto_test(now, SpaceId::Handshake, &handshake_pns);
        let acks = transmit(pair.server_conn_mut(server), now);
        assert_eq!(acks.len(), 1);
        assert_eq!(acks[0].1[0] & 0xb0, 0xa0);
        let remote = pair.server.addr;
        pair.time += Duration::from_millis(20);
        let now = pair.time;
        deliver(&mut pair.client, remote, client, now, acks);
        let state = pair.client_conn_mut(client).pto_timing_for_test();
        assert!(!state.handshake_in_flight && state.has_handshake_keys && !state.confirmed);
    }
    (pair, client, server, held)
}

#[test]
fn pto_timing_unconfirmed_client_must_not_arm_application_pto() {
    for timing in [false, true] {
        let (mut pair, client, server, held) = awaiting_confirmation(timing, false, true);
        let now = pair.time;
        pair.client_conn_mut(client).ping();
        let original = transmit(pair.client_conn_mut(client), now);
        assert_eq!(original.len(), 1);
        assert_eq!(original[0].1[0] & 0x80, 0);
        let remote = pair.client.addr;
        let received = deliver(&mut pair.server, remote, server, now, original);
        assert!(
            received[0]
                .1
                .iter()
                .any(|frame| matches!(frame, Frame::Ping))
        );
        let state = pair.client_conn_mut(client).pto_timing_for_test();
        assert!(!state.handshaking && state.has_handshake_keys && !state.data_acknowledged);
        assert_eq!(state.smoothed, Duration::from_millis(40));
        let deadline = state.deadline.unwrap_or(now + Duration::from_millis(250));
        pair.time = deadline;
        pair.client_conn_mut(client).handle_timeout(deadline);
        let probe = transmit(pair.client_conn_mut(client), deadline);
        let application_packets = probe
            .iter()
            .filter(|(_, bytes)| bytes[0] & 0x80 == 0)
            .count();
        let received = deliver(&mut pair.server, remote, server, deadline, probe);
        eprintln!(
            "unconfirmed timing={timing} S={:?} V={:?} had_deadline={} application_packets={application_packets} frame_types={:?}",
            state.smoothed,
            state.variance,
            state.deadline.is_some(),
            received
                .iter()
                .flat_map(|(_, frames)| frames.iter().map(Frame::ty))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            application_packets, 0,
            "TLS established alone must not allow application PTO"
        );
        for event in held {
            pair.server_conn_mut(server).handle_event(event);
        }
        pair.drive();
        let after = pair.client_conn_mut(client).pto_timing_for_test();
        assert!(!after.handshaking && !after.has_handshake_keys && after.data_acknowledged);
    }
}

#[test]
fn pto_timing_unconfirmed_without_handshake_ack_keeps_handshake_probe() {
    for timing in [false, true] {
        let (mut pair, client, server, held) = awaiting_confirmation(timing, false, false);
        let now = pair.time;
        pair.client_conn_mut(client).ping();
        let data = transmit(pair.client_conn_mut(client), now);
        assert!(data.iter().any(|(_, bytes)| bytes[0] & 0x80 == 0));
        let state = pair.client_conn_mut(client).pto_timing_for_test();
        assert!(!state.confirmed && state.handshake_in_flight && state.has_handshake_keys);
        let deadline = state.deadline.unwrap();
        pair.time = deadline;
        pair.client_conn_mut(client).handle_timeout(deadline);
        let probe = transmit(pair.client_conn_mut(client), deadline);
        assert!(!probe.is_empty());
        assert!(probe.iter().all(|(_, bytes)| bytes[0] & 0xb0 == 0xa0));
        for event in held {
            pair.server_conn_mut(server).handle_event(event);
        }
        pair.drive();
        assert!(pair.client_conn_mut(client).pto_timing_for_test().confirmed);
    }
}

#[test]
fn pto_timing_only_real_one_rtt_ack_confirms_resumed_connection() {
    for timing in [false, true] {
        let (mut pair, client, server, held) = awaiting_confirmation(timing, true, true);
        assert!(pair.client_conn_mut(client).accepted_0rtt());
        assert!(pair.server_conn_mut(server).stats().frame_rx.stream > 0);
        let state = pair.client_conn_mut(client).pto_timing_for_test();
        let boundary = state.first_1rtt_boundary.unwrap();
        assert!(boundary > 0);
        assert!(!state.confirmed && state.has_handshake_keys);
        let now = pair.time;
        pair.server_conn_mut(server)
            .queue_ack_for_pto_test(now, std::slice::from_ref(&(boundary - 1..=boundary - 1)));
        let acks = transmit(pair.server_conn_mut(server), now);
        let remote = pair.server.addr;
        deliver(&mut pair.client, remote, client, now, acks);
        let state = pair.client_conn_mut(client).pto_timing_for_test();
        assert!(state.data_acknowledged && !state.confirmed && state.has_handshake_keys);
        pair.client_conn_mut(client).ping();
        let ping = transmit(pair.client_conn_mut(client), now);
        // Complete the server's TLS dispatch before it processes 1-RTT. Drop
        // its HANDSHAKE_DONE flight so the following ACK is the sole signal.
        for event in held {
            pair.server_conn_mut(server).handle_event(event);
        }
        assert!(pair.server_conn_mut(server).pto_timing_for_test().confirmed);
        let remote = pair.client.addr;
        let received = deliver(&mut pair.server, remote, server, now, ping);
        let pn = received.last().unwrap().0;
        assert!(pn >= boundary);
        let withheld = transmit(pair.server_conn_mut(server), now);
        assert!(!withheld.is_empty());
        assert!(pair.server_conn_mut(server).stats().frame_tx.handshake_done > 0);
        assert!(
            pair.client_conn_mut(client)
                .pto_timing_for_test()
                .has_handshake_keys
        );
        pair.server_conn_mut(server)
            .queue_ack_for_pto_test(now, std::slice::from_ref(&(pn..=pn)));
        let acks = transmit(pair.server_conn_mut(server), now);
        let remote = pair.server.addr;
        deliver(&mut pair.client, remote, client, now, acks);
        let state = pair.client_conn_mut(client).pto_timing_for_test();
        assert!(state.confirmed && state.data_acknowledged);
        eprintln!(
            "resumed timing={timing} 0RTT boundary={boundary}, valid_1rtt_ack={pn}, confirmed={}, retained_handshake_keys={}",
            state.confirmed, state.has_handshake_keys
        );
        assert!(
            !state.has_handshake_keys,
            "acknowledged 1-RTT confirms the handshake and must discard Handshake keys"
        );
        pair.drive();
        assert!(pair.client_conn_mut(client).pto_timing_for_test().confirmed);
    }
}

#[test]
fn pto_timing_lost_handshake_done_is_recovered_by_confirmed_server() {
    let (mut pair, client, server, held) = awaiting_confirmation(true, false, true);
    let mut data_held = Vec::new();
    for event in held {
        let ConnectionEventInner::Datagram(ref datagram) = event.0 else {
            unreachable!()
        };
        if datagram.first_decode.space() == Some(SpaceId::Data) {
            data_held.push(event);
        } else {
            pair.server_conn_mut(server).handle_event(event);
        }
    }
    assert!(pair.server_conn_mut(server).pto_timing_for_test().confirmed);
    let now = pair.time;
    let lost = transmit(pair.server_conn_mut(server), now);
    assert!(!lost.is_empty());
    assert!(lost.iter().all(|(_, bytes)| bytes[0] & 0x80 == 0));
    let before = pair.client_conn_mut(client).pto_timing_for_test();
    assert!(!before.confirmed && !before.data_acknowledged);
    let deadline = pair
        .server_conn_mut(server)
        .loss_timeout_for_pto_test()
        .unwrap();
    pair.time = deadline;
    pair.server_conn_mut(server).handle_timeout(deadline);
    let retry = transmit(pair.server_conn_mut(server), deadline);
    let remote = pair.server.addr;
    let received = deliver(&mut pair.client, remote, client, deadline, retry);
    assert!(received.iter().any(|(_, frames)| {
        frames
            .iter()
            .any(|frame| matches!(frame, Frame::HandshakeDone))
    }));
    let after = pair.client_conn_mut(client).pto_timing_for_test();
    assert!(after.confirmed && !after.has_handshake_keys);
    assert!(
        !after.data_acknowledged,
        "HANDSHAKE_DONE, not a Data ACK, confirmed this client"
    );
    for event in data_held {
        pair.server_conn_mut(server).handle_event(event);
    }
    pair.drive();
    assert!(
        pair.client_conn_mut(client)
            .pto_timing_for_test()
            .data_acknowledged
    );
}

#[test]
fn pto_timing_late_handshake_packet_and_handshake_done_are_safe_after_ack_confirmation() {
    let (mut pair, client, server, held) = awaiting_confirmation(true, false, false);
    assert!(
        pair.client_conn_mut(client)
            .pto_timing_for_test()
            .handshake_in_flight
    );
    let handshake_pn = held
        .iter()
        .find_map(|event| {
            let ConnectionEventInner::Datagram(datagram) = &event.0 else {
                return None;
            };
            (datagram.first_decode.space() == Some(SpaceId::Handshake)).then(|| {
                pair.server_conn_mut(server)
                    .decode_packet_with_number(event)
                    .unwrap()
                    .0
                    .unwrap()
            })
        })
        .unwrap();
    let now = pair.time;
    pair.server_conn_mut(server)
        .queue_ack_in_space_for_pto_test(
            now,
            SpaceId::Handshake,
            std::slice::from_ref(&(handshake_pn..=handshake_pn)),
        );
    let old_handshake_ack = transmit(pair.server_conn_mut(server), now);
    assert_eq!(old_handshake_ack.len(), 1);
    assert_eq!(old_handshake_ack[0].1[0] & 0xb0, 0xa0);
    for event in held {
        pair.server_conn_mut(server).handle_event(event);
    }
    pair.client_conn_mut(client).ping();
    let ping = transmit(pair.client_conn_mut(client), now);
    let remote = pair.client.addr;
    let received = deliver(&mut pair.server, remote, server, now, ping);
    let pn = received.last().unwrap().0;
    pair.server_conn_mut(server)
        .queue_ack_for_pto_test(now, &[]);
    let late_done = transmit(pair.server_conn_mut(server), now);
    assert!(!late_done.is_empty());
    pair.server_conn_mut(server)
        .queue_ack_for_pto_test(now, std::slice::from_ref(&(pn..=pn)));
    let ack = transmit(pair.server_conn_mut(server), now);
    let remote = pair.server.addr;
    deliver(&mut pair.client, remote, client, now, ack);
    let state = pair.client_conn_mut(client).pto_timing_for_test();
    assert!(state.confirmed && !state.has_handshake_keys && !state.handshake_in_flight);
    let in_flight = pair.client_conn_mut(client).bytes_in_flight();
    // A short-header packet must be last in a UDP datagram. Feed the delayed
    // Handshake ACK as a separate real datagram, not invalid coalescing.
    for (ecn, bytes) in old_handshake_ack {
        let Some(DatagramEvent::ConnectionEvent(handle, event)) =
            pair.client
                .handle(now, remote, None, ecn, bytes, &mut Vec::new())
        else {
            panic!("delayed Handshake packet must route");
        };
        assert_eq!(handle, client);
        pair.client_conn_mut(client).handle_event(event);
    }
    assert_eq!(pair.client_conn_mut(client).bytes_in_flight(), in_flight);
    let received = deliver(&mut pair.client, remote, client, now, late_done);
    assert!(received.iter().any(|(_, frames)| {
        frames
            .iter()
            .any(|frame| matches!(frame, Frame::HandshakeDone))
    }));
    assert!(
        !received
            .iter()
            .any(|(_, frames)| frames.iter().any(|frame| matches!(frame, Frame::Ack(_))))
    );
    assert_eq!(pair.client_conn_mut(client).bytes_in_flight(), in_flight);
    assert!(
        !std::iter::from_fn(|| pair.client_conn_mut(client).poll())
            .any(|event| matches!(event, Event::ConnectionLost { .. }))
    );
}

#[test]
fn pto_timing_invalid_one_rtt_ack_does_not_discard_handshake_keys() {
    let (mut pair, client, server, held) = awaiting_confirmation(true, false, true);
    for event in held {
        pair.server_conn_mut(server).handle_event(event);
    }
    let now = pair.time;
    let withheld = transmit(pair.server_conn_mut(server), now);
    assert!(!withheld.is_empty());
    assert!(
        pair.client_conn_mut(client)
            .pto_timing_for_test()
            .has_handshake_keys
    );
    let future = pair
        .client_conn_mut(client)
        .sent_state_for_pto_test(0)
        .0
        .unwrap()
        + 100;
    pair.server_conn_mut(server)
        .queue_ack_for_pto_test(now, std::slice::from_ref(&(future..=future)));
    let invalid = transmit(pair.server_conn_mut(server), now);
    let remote = pair.server.addr;
    deliver(&mut pair.client, remote, client, now, invalid);
    assert!(
        std::iter::from_fn(|| pair.client_conn_mut(client).poll()).any(|event| {
            matches!(event, Event::ConnectionLost { reason: ConnectionError::TransportError(error) }
            if error.code == TransportErrorCode::PROTOCOL_VIOLATION)
        })
    );
    assert!(
        pair.client_conn_mut(client)
            .pto_timing_for_test()
            .has_handshake_keys
    );
}

#[test]
fn pto_timing_latest_acked_packet_does_not_rewind_cached_flight_edge() {
    for timing in [false, true] {
        let mut case = TimingCase::configured(Duration::from_millis(20), timing);
        for _ in 0..8 {
            case.rtt_sample(Duration::from_millis(20));
        }
        let first = case.send_unacknowledged_ping();
        case.pair.time += Duration::from_millis(35);
        let last = case.send_unacknowledged_ping();
        let pn = case
            .pair
            .client_conn_mut(case.client)
            .sent_state_for_pto_test(0)
            .0
            .unwrap();
        case.pair.time += Duration::from_millis(1);
        let now = case.pair.time;
        case.pair
            .server_conn_mut(case.server)
            .queue_ack_for_pto_test(now, std::slice::from_ref(&(pn..=pn)));
        let acks = transmit(case.pair.server_conn_mut(case.server), now);
        let remote = case.pair.server.addr;
        deliver(&mut case.pair.client, remote, case.client, now, acks);
        let state = case.snapshot();
        assert_eq!(state.first_in_flight, Some(first));
        assert_eq!(state.last_in_flight, Some(first));
        assert_eq!(state.last_ack_eliciting, Some(last));
        let (candidate, space) = case
            .pair
            .client_conn_mut(case.client)
            .pto_candidate_for_timing_test(now)
            .unwrap();
        assert_eq!(space, SpaceId::Data);
        let expected = if timing {
            chrome_source_deadline(&state, now)
        } else {
            legacy_deadline(&state)
        };
        assert_eq!(candidate, expected);
        assert!(
            state.deadline.unwrap() < candidate,
            "real loss-time deadline keeps priority over PTO"
        );
        if timing {
            let mut rewound = state.clone();
            rewound.last_ack_eliciting = Some(first);
            assert!(chrome_source_deadline(&rewound, now) < candidate);
        }
    }
}

#[test]
fn pto_timing_microsecond_quantization_does_not_change_native_estimator() {
    for extra in [1, 999] {
        for timing in [false, true] {
            let mut case = TimingCase::configured(Duration::from_millis(20), timing);
            case.rtt_sample(Duration::from_millis(20) + Duration::from_nanos(extra * 4));
            assert_eq!(
                case.snapshot().smoothed,
                Duration::from_millis(40) + Duration::from_nanos(extra)
            );
            case.send_unacknowledged_ping();
            case.pair.time += Duration::from_millis(50);
            let last = case.send_unacknowledged_ping();
            let state = case.snapshot();
            if timing {
                assert_eq!(state.deadline.unwrap() - last, Duration::from_millis(60));
            } else {
                assert_eq!(state.deadline, Some(legacy_deadline(&state)));
            }
        }
    }
    let mut case = TimingCase::configured(Duration::from_nanos(20_000_500), true);
    assert_eq!(case.snapshot().smoothed, Duration::from_micros(40_001));
    case.send_unacknowledged_ping();
    case.pair.time += Duration::from_millis(50);
    let last = case.send_unacknowledged_ping();
    assert_eq!(
        case.snapshot().deadline.unwrap() - last,
        Duration::from_micros(60_002)
    );
}

#[test]
fn pto_timing_granularity_and_negotiated_ack_delay_scale_with_backoff() {
    for delay in [None, Some(Duration::from_millis(10))] {
        let mut case = TimingCase::with_ack_delay(Duration::from_micros(500), true, delay);
        let first = case.send_unacknowledged_ping();
        let state = case.snapshot();
        assert_eq!(state.smoothed, Duration::from_millis(1));
        assert!(state.variance * 2 < Duration::from_millis(1));
        let base = Duration::from_millis(2) + state.max_ack_delay;
        assert_eq!(state.deadline, Some(first + base));
        case.pair.time = state.deadline.unwrap();
        let now = case.pair.time;
        case.pair.client_conn_mut(case.client).handle_timeout(now);
        assert_eq!(case.snapshot().deadline, None);
        let packets = transmit(case.pair.client_conn_mut(case.client), now);
        assert_eq!(packets.len(), 1);
        assert_eq!(case.snapshot().deadline, Some(now + base * 2));
    }
}

#[test]
fn pto_timing_unsampled_initial_retains_default_rtt_and_probe_schedule() {
    for timing in [false, true] {
        let mut pair = Pair::default_with_deterministic_pns();
        let mut config = client_config_with_deterministic_pns();
        Arc::get_mut(&mut config.transport)
            .unwrap()
            .chrome_pto_timing(timing);
        let client = pair.begin_connect(config);
        let sent = pair.time;
        pair.drive_client();
        let state = pair.client_conn_mut(client).pto_timing_for_test();
        assert!(!state.sampled && !state.has_data_keys && !state.confirmed);
        assert_eq!(state.smoothed, Duration::from_millis(333));
        assert_eq!(state.deadline, Some(sent + Duration::from_millis(999)));
        assert_eq!(
            pair.client_conn_mut(client)
                .pto_candidate_for_timing_test(sent)
                .unwrap()
                .1,
            SpaceId::Initial
        );
    }
}

#[test]
fn pto_timing_real_peer_samples_follow_native_estimator_and_four_variance_deadline() {
    let mut case = TimingCase::new(Duration::from_millis(20));
    let initial = case.snapshot();
    assert!(initial.sampled && initial.has_data_keys && initial.data_acknowledged);
    assert!(!initial.handshaking && !initial.has_handshake_keys);
    assert!(!initial.handshake_in_flight);
    assert_eq!(initial.smoothed, Duration::from_millis(40));
    for latency in [30, 10, 20] {
        let before = case.snapshot();
        let sample = Duration::from_millis(2 * latency);
        case.rtt_sample(Duration::from_millis(latency));
        let after = case.snapshot();
        assert_eq!(after.smoothed, (7 * before.smoothed + sample) / 8);
        assert_eq!(
            after.variance,
            (3 * before.variance + before.smoothed.abs_diff(sample)) / 4
        );
        assert_eq!(after.backoff, 0);
    }
    let sent = case.send_unacknowledged_ping();
    let state = case.snapshot();
    assert_eq!(state.first_in_flight, Some(sent));
    assert_eq!(state.last_in_flight, Some(sent));
    assert_eq!(state.deadline, Some(legacy_deadline(&state)));
    let chrome = chrome_source_deadline(&state, case.pair.time);
    assert_ne!(state.deadline, Some(chrome));
    eprintln!(
        "single flight measured S={:?} V={:?} A={:?} Quinn={:?} Chrome-source-same-inputs={:?}",
        state.smoothed,
        state.variance,
        state.max_ack_delay,
        state.deadline.unwrap() - sent,
        chrome - sent
    );
}

#[test]
fn pto_timing_first_flight_edges_and_later_backoff_are_independent_inputs() {
    for spread in [5, 50] {
        let mut case = TimingCase::new(Duration::from_millis(20));
        let first = case.send_unacknowledged_ping();
        case.pair.time += Duration::from_millis(spread);
        let last = case.send_unacknowledged_ping();
        let state = case.snapshot();
        assert_eq!(
            (state.first_in_flight, state.last_in_flight),
            (Some(first), Some(last))
        );
        assert_eq!(state.deadline, Some(legacy_deadline(&state)));
        let chrome = chrome_source_deadline(&state, case.pair.time);
        assert_ne!(state.deadline, Some(chrome));
        eprintln!(
            "first PTO spread={spread}ms S={:?} V={:?} A={:?} Quinn_from_first={:?} Chrome_from_first={:?}",
            state.smoothed,
            state.variance,
            state.max_ack_delay,
            state.deadline.unwrap() - first,
            chrome - first
        );
        let deadline = state.deadline.unwrap();
        case.pair.time = deadline;
        case.pair
            .client_conn_mut(case.client)
            .handle_timeout(deadline);
        assert_eq!(case.snapshot().deadline, None);
        let outgoing = transmit(case.pair.client_conn_mut(case.client), deadline);
        assert_eq!(outgoing.len(), 1);
        let remote = case.pair.client.addr;
        deliver(
            &mut case.pair.server,
            remote,
            case.server,
            deadline,
            outgoing,
        );
        let later = case.snapshot();
        assert_eq!(later.backoff, 1);
        assert_eq!(later.first_in_flight, Some(first));
        assert_eq!(later.last_in_flight, Some(deadline));
        assert_eq!(later.deadline, Some(legacy_deadline(&later)));
        let chrome_later = chrome_source_deadline(&later, deadline);
        assert_ne!(later.deadline, Some(chrome_later));
        eprintln!(
            "later PTO k=1 Quinn_interval={:?} Chrome-source-interval={:?}",
            later.deadline.unwrap() - deadline,
            chrome_later - deadline
        );
    }
}
