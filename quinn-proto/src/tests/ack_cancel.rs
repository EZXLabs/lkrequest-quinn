use super::*;

#[derive(Debug)]
struct ObservedPacket {
    types: Vec<&'static str>,
    ack: Option<frame::Ack>,
    padding: usize,
}

fn observe(payload: Vec<u8>) -> ObservedPacket {
    let mut packet = ObservedPacket {
        types: Vec::new(),
        ack: None,
        padding: 0,
    };
    for frame in frame::Iter::new(payload.into()).unwrap() {
        match frame.unwrap() {
            Frame::Ack(ack) => {
                packet
                    .types
                    .push(if ack.ecn.is_some() { "ACK_ECN" } else { "ACK" });
                assert!(packet.ack.replace(ack).is_none());
            }
            Frame::StopSending(stop) => {
                assert_eq!(stop.error_code.into_inner(), 268);
                packet.types.push("STOP");
            }
            Frame::ResetStream(reset) => {
                assert_eq!(reset.error_code.into_inner(), 268);
                assert_eq!(reset.final_offset.into_inner(), 6);
                packet.types.push("RESET");
            }
            Frame::Ping => packet.types.push("PING"),
            Frame::ImmediateAck => packet.types.push("IMMEDIATE_ACK"),
            Frame::AckFrequency(_) => packet.types.push("ACK_FREQUENCY"),
            Frame::Padding => packet.padding += 1,
            unexpected => panic!("unexpected fixture frame: {unexpected:?}"),
        }
    }
    packet
}

// Handle real authenticated packet events without composing a response yet.
fn receive(
    endpoint: &mut TestEndpoint,
    remote: SocketAddr,
    expected: ConnectionHandle,
) -> Vec<ObservedPacket> {
    let mut packets = Vec::new();
    while let Some((time, ecn, bytes)) = endpoint.inbound.pop_front() {
        let mut response = Vec::new();
        let Some(DatagramEvent::ConnectionEvent(handle, event)) =
            endpoint.handle(time, remote, None, ecn, bytes, &mut response)
        else {
            panic!("established peer packet must reach its connection");
        };
        assert_eq!(handle, expected);
        let connection = endpoint.connections.get_mut(&handle).unwrap();
        packets.push(observe(connection.decode_packet(&event).unwrap()));
        connection.handle_event(event);
        assert!(response.is_empty());
    }
    packets
}

fn inspect_withheld(
    endpoint: &mut TestEndpoint,
    remote: SocketAddr,
    expected: ConnectionHandle,
) -> Vec<ObservedPacket> {
    let mut packets = Vec::new();
    while let Some((time, ecn, bytes)) = endpoint.inbound.pop_front() {
        let Some(DatagramEvent::ConnectionEvent(handle, event)) =
            endpoint.handle(time, remote, None, ecn, bytes, &mut Vec::new())
        else {
            panic!("expected withheld connection event");
        };
        assert_eq!(handle, expected);
        packets.push(observe(
            endpoint.connections[&handle].decode_packet(&event).unwrap(),
        ));
    }
    packets
}

fn transmit(connection: &mut Connection, time: Instant) -> Vec<(Option<EcnCodepoint>, BytesMut)> {
    let mut packets = Vec::new();
    let mut bytes = Vec::new();
    while let Some(sent) = connection.poll_transmit(time, 1, &mut bytes) {
        assert!(sent.segment_size.is_none());
        packets.push((sent.ecn, BytesMut::from(&bytes[..sent.size])));
        bytes.clear();
    }
    packets
}

struct AckCase {
    pair: Pair,
    client: ConnectionHandle,
    server: ConnectionHandle,
    stream: StreamId,
    baseline_ack: frame::Ack,
    baseline_time: Instant,
    bundled_delay: Duration,
}

impl AckCase {
    fn new_chrome(server_ecn: bool) -> Self {
        Self::configured(server_ecn, true, true, None)
    }

    fn new(server_ecn: bool, deliver_baseline_ack: bool) -> Self {
        Self::configured(server_ecn, deliver_baseline_ack, false, None)
    }

    fn configured(
        server_ecn: bool,
        deliver_baseline_ack: bool,
        ack_obligation_only: bool,
        ack_frequency: Option<AckFrequencyConfig>,
    ) -> Self {
        let mut server = server_config();
        let mut transport = TransportConfig::default();
        transport
            .deterministic_packet_numbers(true)
            .mtu_discovery_config(None)
            .enable_ecn(server_ecn)
            .ack_frequency_config(ack_frequency);
        server.transport_config(Arc::new(transport));
        let mut client_config = client_config_with_deterministic_pns();
        Arc::get_mut(&mut client_config.transport)
            .unwrap()
            .mtu_discovery_config(None)
            .enable_ecn(false)
            .stop_before_matching_reset(true)
            .ack_obligation_only(ack_obligation_only);
        let mut pair = Pair::new(Default::default(), server);
        let (client, server) = pair.connect_with(client_config);
        let stream = pair.client_streams(client).open(Dir::Bi).unwrap();
        pair.client_send(client, stream).write(b"upload").unwrap();
        pair.drive();
        assert_eq!(pair.server_streams(server).accept(Dir::Bi), Some(stream));
        pair.server_send(server, stream).write(b"response").unwrap();
        pair.drive();

        // A fresh IMMEDIATE_ACK produces a pure client ACK at a known time.
        pair.server_conn_mut(server).immediate_ack();
        let now = pair.time;
        for (ecn, bytes) in transmit(pair.server_conn_mut(server), now) {
            pair.client.inbound.push_back((now, ecn, bytes));
        }
        let server_addr = pair.server.addr;
        let incoming = receive(&mut pair.client, server_addr, client);
        assert_eq!(incoming.len(), 1);
        assert!(incoming[0].types.contains(&"IMMEDIATE_ACK"));
        let baseline_packets = transmit(pair.client_conn_mut(client), now);
        assert_eq!(baseline_packets.len(), 1);
        for (ecn, bytes) in baseline_packets {
            assert_eq!(ecn, None, "client transmit ECN is disabled");
            pair.server.inbound.push_back((now, ecn, bytes));
        }
        let baseline_ack = if deliver_baseline_ack {
            let client_addr = pair.client.addr;
            let incoming = receive(&mut pair.server, client_addr, server);
            assert_eq!(incoming.len(), 1);
            assert_eq!(incoming[0].types.len(), 1);
            incoming.into_iter().next().unwrap().ack
        } else {
            // Decode the withheld packet without delivering its connection event.
            let client_addr = pair.client.addr;
            let mut packets = inspect_withheld(&mut pair.server, client_addr, server);
            assert_eq!(packets.len(), 1);
            let packet = packets.pop().unwrap();
            assert_eq!(packet.types.len(), 1);
            packet.ack
        };
        let bundled_delay = pair.client_conn_mut(client).rtt()
            + Duration::from_millis(TransportParameters::default().max_ack_delay.into_inner())
            + TIMER_GRANULARITY;
        Self {
            pair,
            client,
            server,
            stream,
            baseline_ack: baseline_ack.unwrap(),
            baseline_time: now,
            bundled_delay,
        }
    }

    fn ack_only_tail(&mut self, count: usize) {
        self.ack_only_tail_with_ce(count, false);
    }

    fn ack_only_tail_with_ce(&mut self, count: usize, ce: bool) {
        for _ in 0..count {
            self.pair.client_conn_mut(self.client).immediate_ack();
            let now = self.pair.time;
            let outgoing = transmit(self.pair.client_conn_mut(self.client), now);
            assert_eq!(outgoing.len(), 1);
            for (ecn, bytes) in outgoing {
                self.pair.server.inbound.push_back((now, ecn, bytes));
            }
            let remote = self.pair.client.addr;
            let incoming = receive(&mut self.pair.server, remote, self.server);
            assert_eq!(incoming.len(), 1);
            assert!(incoming[0].types.contains(&"IMMEDIATE_ACK"));
            let outgoing = transmit(self.pair.server_conn_mut(self.server), now);
            assert_eq!(outgoing.len(), 1);
            for (ecn, bytes) in outgoing {
                self.pair.client.inbound.push_back((
                    now,
                    if ce { Some(EcnCodepoint::Ce) } else { ecn },
                    bytes,
                ));
            }
        }
        let remote = self.pair.server.addr;
        let received = receive(&mut self.pair.client, remote, self.client);
        assert_eq!(received.len(), count);
        for packet in received {
            assert_eq!(packet.types.len(), 1);
            assert!(
                packet.ack.is_some(),
                "tail must be actual peer ACK-only packets"
            );
        }
    }

    fn peer_ping(&mut self, ce: bool, skip_first: bool) {
        let now = self.pair.time;
        if skip_first {
            self.pair.server_conn_mut(self.server).ping();
            assert_eq!(
                transmit(self.pair.server_conn_mut(self.server), now).len(),
                1
            );
        }
        self.pair.server_conn_mut(self.server).ping();
        let outgoing = transmit(self.pair.server_conn_mut(self.server), now);
        assert_eq!(outgoing.len(), 1);
        for (ecn, bytes) in outgoing {
            self.pair.client.inbound.push_back((
                now,
                if ce { Some(EcnCodepoint::Ce) } else { ecn },
                bytes,
            ));
        }
        let remote = self.pair.server.addr;
        let incoming = receive(&mut self.pair.client, remote, self.client);
        assert_eq!(incoming.len(), 1);
        assert!(incoming[0].types.contains(&"PING"));
    }

    fn peer_immediate_ack(&mut self) {
        let now = self.pair.time;
        self.pair.server_conn_mut(self.server).immediate_ack();
        let outgoing = transmit(self.pair.server_conn_mut(self.server), now);
        assert_eq!(outgoing.len(), 1);
        for (ecn, bytes) in outgoing {
            self.pair.client.inbound.push_back((now, ecn, bytes));
        }
        let remote = self.pair.server.addr;
        let incoming = receive(&mut self.pair.client, remote, self.client);
        assert_eq!(incoming.len(), 1);
        assert!(incoming[0].types.contains(&"IMMEDIATE_ACK"));
    }

    fn cancel(mut self, elapsed: Duration, timeout: bool) -> ObservedPacket {
        self.pair.time = self.baseline_time + elapsed;
        let now = self.pair.time;
        if timeout {
            self.pair.client_conn_mut(self.client).handle_timeout(now);
        }
        self.pair
            .client_recv(self.client, self.stream)
            .stop(268u32.into())
            .unwrap();
        self.pair
            .client_send(self.client, self.stream)
            .reset(268u32.into())
            .unwrap();
        let outgoing = transmit(self.pair.client_conn_mut(self.client), now);
        assert_eq!(outgoing.len(), 1, "cancel should fit a single packet");
        for (ecn, bytes) in outgoing {
            assert_eq!(ecn, None);
            self.pair.server.inbound.push_back((now, ecn, bytes));
        }
        let remote = self.pair.client.addr;
        let mut packets = receive(&mut self.pair.server, remote, self.server);
        assert_eq!(packets.len(), 1);
        packets.pop().unwrap()
    }
}

#[test]
fn ack_cancel_state_ack_only_tail_and_bundle_deadline() {
    for server_ecn in [false, true] {
        for count in [0, 1, 10, 11] {
            for elapsed_deadline in [false, true] {
                let mut case = AckCase::new(server_ecn, true);
                case.ack_only_tail(count);
                let elapsed = if elapsed_deadline {
                    case.bundled_delay + Duration::from_millis(1)
                } else {
                    Duration::ZERO
                };
                let packet = case.cancel(elapsed, false);
                let ack = if server_ecn { "ACK_ECN" } else { "ACK" };
                let expected = if count > 10 {
                    vec![ack, "STOP", "RESET"]
                } else if elapsed_deadline {
                    vec!["STOP", "RESET", ack]
                } else {
                    vec!["STOP", "RESET"]
                };
                eprintln!(
                    "ACK-only tail={count}, server_ecn={server_ecn}, deadline_elapsed={elapsed_deadline}: {packet:?}"
                );
                assert_eq!(packet.types, expected);
            }
        }
    }
}

#[test]
fn ack_cancel_state_fresh_eliciting_packet_and_max_delay() {
    for expire_timer in [false, true] {
        let mut case = AckCase::new(false, true);
        case.peer_ping(false, false);
        let elapsed = if expire_timer {
            Duration::from_millis(TransportParameters::default().max_ack_delay.into_inner())
        } else {
            Duration::ZERO
        };
        let packet = case.cancel(elapsed, expire_timer);
        eprintln!("fresh PING, max_delay_expired={expire_timer}: {packet:?}");
        assert_eq!(
            packet.types,
            if expire_timer {
                vec!["ACK", "STOP", "RESET"]
            } else {
                vec!["STOP", "RESET", "ACK"]
            }
        );
    }
}

#[test]
fn ack_cancel_state_ce_reordering_and_eliciting_threshold_remain_immediate() {
    for stimulus in ["ce", "gap", "two-pings"] {
        let mut case = AckCase::new(true, true);
        case.peer_ping(stimulus == "ce", stimulus == "gap");
        if stimulus == "two-pings" {
            case.peer_ping(false, false);
        }
        let packet = case.cancel(Duration::ZERO, false);
        eprintln!("immediate ACK protection {stimulus}: {packet:?}");
        assert_eq!(packet.types, vec!["ACK_ECN", "STOP", "RESET"]);
        if stimulus == "ce" {
            assert!(packet.ack.unwrap().ecn.unwrap().ce > 0);
        }
    }
}

#[test]
fn ack_cancel_state_ack_of_ack_prunes_old_ranges_but_retains_its_own_packet() {
    for delivered in [false, true] {
        let mut case = AckCase::new(false, delivered);
        let old_largest = case.baseline_ack.largest;
        case.ack_only_tail(1);
        let elapsed = case.bundled_delay + Duration::from_millis(1);
        let packet = case.cancel(elapsed, false);
        assert_eq!(packet.types, vec!["STOP", "RESET", "ACK"]);
        let ack = packet.ack.unwrap();
        let retains_old = ack.iter().any(|range| range.contains(&old_largest));
        eprintln!("old ACK delivered={delivered}, old_largest={old_largest}, next_ack={ack:?}");
        assert_eq!(retains_old, !delivered);
        assert!(
            ack.largest > old_largest,
            "the ACK-of-ACK packet itself still needs a range"
        );
    }
}

#[test]
fn ack_cancel_chrome_does_not_bundle_ranges_without_ack_obligation() {
    let mut differences = Vec::new();
    for server_ecn in [false, true] {
        for count in [0, 1, 10] {
            let mut case = AckCase::new_chrome(server_ecn);
            case.ack_only_tail(count);
            let elapsed = case.bundled_delay + Duration::from_millis(1);
            let packet = case.cancel(elapsed, false);
            if packet.types != ["STOP", "RESET"] {
                differences.push((server_ecn, count, packet.types));
            }
        }
    }
    assert!(
        differences.is_empty(),
        "Chrome obligation-only differences: {differences:?}"
    );
}

#[test]
fn ack_cancel_chrome_ack_only_tail_does_not_request_immediate_ack() {
    let mut differences = Vec::new();
    for server_ecn in [false, true] {
        for expired in [false, true] {
            let mut case = AckCase::new_chrome(server_ecn);
            case.ack_only_tail(11);
            let elapsed = if expired {
                case.bundled_delay + Duration::from_millis(1)
            } else {
                Duration::ZERO
            };
            let packet = case.cancel(elapsed, false);
            if packet.types != ["STOP", "RESET"] {
                differences.push((server_ecn, expired, packet.types));
            }
        }
    }
    assert!(
        differences.is_empty(),
        "Chrome voluntary ACK differences: {differences:?}"
    );
}

#[test]
fn ack_cancel_chrome_new_eliciting_data_still_bundles_ack() {
    let mut case = AckCase::new_chrome(false);
    case.peer_ping(false, false);
    let packet = case.cancel(Duration::ZERO, false);
    assert_eq!(packet.types, vec!["STOP", "RESET", "ACK"]);
}

#[test]
fn ack_cancel_chrome_ping_after_ack_only_tail_restores_obligation() {
    for count in [1, 10, 11] {
        let mut case = AckCase::new_chrome(false);
        case.ack_only_tail(count);
        case.peer_ping(false, false);
        let packet = case.cancel(Duration::ZERO, false);
        assert_eq!(packet.types, vec!["STOP", "RESET", "ACK"], "tail={count}");
    }
}

#[test]
fn ack_cancel_chrome_ack_only_after_pending_ping_keeps_its_original_deadline() {
    for count in [1, 11] {
        for expire_timer in [false, true] {
            let mut case = AckCase::new_chrome(false);
            let now = case.pair.time;
            // Prepare client requests before PING exists, then hold delivery.
            // No client transmit is polled once PING becomes a pending obligation.
            for _ in 0..count {
                case.pair.client_conn_mut(case.client).immediate_ack();
                let outgoing = transmit(case.pair.client_conn_mut(case.client), now);
                assert_eq!(outgoing.len(), 1);
                for (ecn, bytes) in outgoing {
                    case.pair.server.inbound.push_back((now, ecn, bytes));
                }
            }
            let requests = mem::take(&mut case.pair.server.inbound);
            case.peer_ping(false, false);
            let ack_count = case.pair.client_conn_mut(case.client).stats().frame_tx.acks;
            let original_deadline = case.baseline_time + Duration::from_millis(25);
            assert_eq!(
                case.pair.client_conn_mut(case.client).poll_timeout(),
                Some(original_deadline)
            );
            case.pair.time += Duration::from_millis(5);
            let now = case.pair.time;
            for (_, ecn, bytes) in requests {
                case.pair.server.inbound.push_back((now, ecn, bytes));
                let remote = case.pair.client.addr;
                let received = receive(&mut case.pair.server, remote, case.server);
                assert_eq!(received.len(), 1);
                assert_eq!(received[0].types, vec!["IMMEDIATE_ACK"]);
                let outgoing = transmit(case.pair.server_conn_mut(case.server), now);
                assert_eq!(outgoing.len(), 1);
                for (ecn, bytes) in outgoing {
                    case.pair.client.inbound.push_back((now, ecn, bytes));
                }
            }
            let remote = case.pair.server.addr;
            let received = receive(&mut case.pair.client, remote, case.client);
            assert_eq!(received.len(), count);
            for packet in received {
                assert_eq!(packet.types, vec!["ACK"]);
            }
            assert_eq!(
                case.pair.client_conn_mut(case.client).stats().frame_tx.acks,
                ack_count
            );
            assert_eq!(
                case.pair.client_conn_mut(case.client).poll_timeout(),
                Some(original_deadline)
            );
            let elapsed = Duration::from_millis(if expire_timer { 25 } else { 5 });
            let packet = case.cancel(elapsed, expire_timer);
            assert_eq!(
                packet.types,
                if expire_timer {
                    vec!["ACK", "STOP", "RESET"]
                } else {
                    vec!["STOP", "RESET", "ACK"]
                }
            );
            if expire_timer {
                assert_eq!(packet.ack.unwrap().delay << 3, 20_000);
            }
        }
    }
}

#[test]
fn ack_cancel_chrome_real_immediate_obligations_and_timer_are_preserved() {
    for stimulus in [
        "ce",
        "ack-only-ce",
        "gap",
        "two-pings",
        "immediate",
        "max-delay",
    ] {
        let mut case = AckCase::new_chrome(true);
        if stimulus == "immediate" {
            case.peer_immediate_ack();
        } else if stimulus == "ack-only-ce" {
            case.ack_only_tail_with_ce(1, true);
        } else {
            case.peer_ping(stimulus == "ce", stimulus == "gap");
        }
        if stimulus == "two-pings" {
            case.peer_ping(false, false);
        }
        let elapsed = if stimulus == "max-delay" {
            Duration::from_millis(25)
        } else {
            Duration::ZERO
        };
        let packet = case.cancel(elapsed, stimulus == "max-delay");
        assert_eq!(packet.types, vec!["ACK_ECN", "STOP", "RESET"], "{stimulus}");
        if matches!(stimulus, "ce" | "ack-only-ce") {
            assert!(packet.ack.unwrap().ecn.unwrap().ce > 0);
        }
    }
}

#[test]
fn ack_cancel_chrome_ack_frequency_changes_threshold_and_deadline() {
    for stimulus in [
        "below-threshold",
        "above-threshold",
        "custom-delay",
        "reordering-disabled",
    ] {
        let mut frequency = AckFrequencyConfig::default();
        frequency
            .ack_eliciting_threshold(3u32.into())
            .max_ack_delay(Some(Duration::from_millis(10)));
        if stimulus == "reordering-disabled" {
            frequency.reordering_threshold(0u32.into());
        }
        let mut case = AckCase::configured(false, true, true, Some(frequency));
        assert!(
            case.pair
                .client_conn_mut(case.client)
                .stats()
                .frame_rx
                .ack_frequency
                > 0
        );
        let count = if stimulus == "above-threshold" { 4 } else { 1 };
        for _ in 0..count {
            case.peer_ping(false, stimulus == "reordering-disabled");
        }
        let elapsed = if stimulus == "custom-delay" {
            Duration::from_millis(10)
        } else {
            Duration::ZERO
        };
        let packet = case.cancel(elapsed, stimulus == "custom-delay");
        let immediate = matches!(stimulus, "above-threshold" | "custom-delay");
        assert_eq!(
            packet.types,
            if immediate {
                vec!["ACK", "STOP", "RESET"]
            } else {
                vec!["STOP", "RESET", "ACK"]
            },
            "{stimulus}"
        );
        if stimulus == "custom-delay" {
            assert_eq!(packet.ack.unwrap().delay << 3, 10_000);
        }
    }
}

#[test]
fn ack_cancel_chrome_ack_capacity_failure_preserves_obligation_and_ranges() {
    let mut case = AckCase::new_chrome(false);
    case.peer_ping(false, false);
    let now = case.pair.time;
    let count = case.pair.client_conn_mut(case.client).stats().frame_tx.acks;
    let (payload, sent_largest) = case
        .pair
        .client_conn_mut(case.client)
        .try_ack_capacity_for_test(now, 0);
    assert!(payload.is_empty());
    assert!(sent_largest.is_none());
    assert_eq!(
        case.pair.client_conn_mut(case.client).stats().frame_tx.acks,
        count
    );
    let old_largest = case.baseline_ack.largest;
    let packet = case.cancel(Duration::ZERO, false);
    assert_eq!(packet.types, vec!["STOP", "RESET", "ACK"]);
    assert!(
        packet
            .ack
            .unwrap()
            .iter()
            .any(|range| range.contains(&(old_largest + 1)))
    );
}

#[test]
fn ack_cancel_chrome_lost_ack_peer_pto_restores_ack_obligation() {
    let mut case = AckCase::new_chrome(false);
    case.peer_ping(false, false);
    let now = case.baseline_time + Duration::from_millis(25);
    case.pair.client_conn_mut(case.client).handle_timeout(now);
    let outgoing = transmit(case.pair.client_conn_mut(case.client), now);
    assert_eq!(outgoing.len(), 1);
    for (ecn, bytes) in outgoing {
        case.pair.server.inbound.push_back((now, ecn, bytes));
    }
    let remote = case.pair.client.addr;
    let mut dropped = inspect_withheld(&mut case.pair.server, remote, case.server);
    assert_eq!(dropped.len(), 1);
    let packet = dropped.pop().unwrap();
    assert_eq!(packet.types, vec!["ACK"]);
    let lost_largest = packet.ack.unwrap().largest;

    let timeout = case
        .pair
        .server_conn_mut(case.server)
        .poll_timeout()
        .unwrap();
    assert!(timeout >= now);
    case.pair.time = timeout;
    case.pair
        .server_conn_mut(case.server)
        .handle_timeout(timeout);
    let probes = transmit(case.pair.server_conn_mut(case.server), timeout);
    assert!(
        !probes.is_empty(),
        "the peer must actually transmit a PTO probe"
    );
    for (ecn, bytes) in probes {
        case.pair.client.inbound.push_back((timeout, ecn, bytes));
    }
    let remote = case.pair.server.addr;
    let probes = receive(&mut case.pair.client, remote, case.client);
    assert!(probes.iter().any(|packet| packet.types.contains(&"PING") || packet.types.contains(&"IMMEDIATE_ACK")));
    let elapsed = timeout - case.baseline_time;
    let packet = case.cancel(elapsed, false);
    let ack = packet
        .ack
        .expect("a fresh peer probe must restore ACK eligibility");
    assert!(
        ack.largest > lost_largest,
        "probe must use a new packet number"
    );
    assert!(ack.iter().any(|range| range.contains(&lost_largest)));
    eprintln!("lost ACK largest={lost_largest}, real PTO={probes:?}, recovery={ack:?}");
}
