use super::*;
use crate::packet::SpaceId;

#[derive(Debug)]
struct PacketSummary {
    number: u64,
    encrypted_bytes: usize,
    types: Vec<&'static str>,
    ack_eliciting: bool,
    reset: Option<(StreamId, u64, u64)>,
    ack: Option<frame::Ack>,
}

fn summarize(number: u64, encrypted_bytes: usize, payload: Vec<u8>) -> PacketSummary {
    let mut result = PacketSummary {
        number,
        encrypted_bytes,
        types: Vec::new(),
        ack_eliciting: false,
        reset: None,
        ack: None,
    };
    for frame in frame::Iter::new(payload.into()).unwrap() {
        let frame = frame.unwrap();
        result.ack_eliciting |= frame.is_ack_eliciting();
        match frame {
            Frame::Padding => (),
            Frame::Ack(ack) => {
                result
                    .types
                    .push(if ack.ecn.is_some() { "ACK_ECN" } else { "ACK" });
                assert!(result.ack.replace(ack).is_none());
            }
            Frame::ResetStream(reset) => {
                result.types.push("RESET");
                assert!(
                    result
                        .reset
                        .replace((
                            reset.id,
                            reset.error_code.into_inner(),
                            reset.final_offset.into_inner()
                        ))
                        .is_none()
                );
            }
            Frame::StopSending(_) => result.types.push("STOP"),
            Frame::Ping => result.types.push("PING"),
            Frame::ImmediateAck => result.types.push("IMMEDIATE_ACK"),
            Frame::Stream(_) => result.types.push("STREAM"),
            Frame::AckFrequency(_) => result.types.push("ACK_FREQUENCY"),
            other => panic!("unexpected PTO fixture frame: {other:?}"),
        }
    }
    result
}

fn transmit(connection: &mut Connection, now: Instant) -> Vec<(Option<EcnCodepoint>, BytesMut)> {
    let mut packets = Vec::new();
    let mut bytes = Vec::new();
    while let Some(sent) = connection.poll_transmit(now, 1, &mut bytes) {
        assert!(sent.segment_size.is_none());
        packets.push((sent.ecn, BytesMut::from(&bytes[..sent.size])));
        bytes.clear();
    }
    packets
}

fn receive(
    endpoint: &mut TestEndpoint,
    remote: SocketAddr,
    expected: ConnectionHandle,
    deliver: bool,
) -> Vec<PacketSummary> {
    let mut result = Vec::new();
    while let Some((now, ecn, bytes)) = endpoint.inbound.pop_front() {
        let encrypted_bytes = bytes.len();
        let Some(DatagramEvent::ConnectionEvent(handle, event)) =
            endpoint.handle(now, remote, None, ecn, bytes, &mut Vec::new())
        else {
            panic!("expected an established peer packet");
        };
        assert_eq!(handle, expected);
        let connection = endpoint.connections.get_mut(&handle).unwrap();
        let (number, payload) = connection.decode_packet_with_number(&event).unwrap();
        result.push(summarize(
            number.expect("established packet must be protected"),
            encrypted_bytes,
            payload,
        ));
        if deliver {
            connection.handle_event(event);
        }
    }
    result
}

struct PtoCase {
    pair: Pair,
    client: ConnectionHandle,
    server: ConnectionHandle,
    single_probe: bool,
}

impl PtoCase {
    fn new(
        peer_min_ack: bool,
        local_min_ack: bool,
        configured_ack_frequency: bool,
        peer_ecn: bool,
    ) -> Self {
        Self::configured(
            peer_min_ack,
            local_min_ack,
            configured_ack_frequency,
            peer_ecn,
            false,
        )
    }

    fn configured(
        peer_min_ack: bool,
        local_min_ack: bool,
        configured_ack_frequency: bool,
        peer_ecn: bool,
        single_probe: bool,
    ) -> Self {
        let mut server = server_config();
        let mut transport = TransportConfig::default();
        transport
            .deterministic_packet_numbers(true)
            .mtu_discovery_config(None)
            .send_min_ack_delay_transport_parameter(peer_min_ack)
            .enable_ecn(peer_ecn)
            .ack_obligation_only(true);
        server.transport_config(Arc::new(transport));
        let mut client = client_config_with_deterministic_pns();
        Arc::get_mut(&mut client.transport)
            .unwrap()
            .mtu_discovery_config(None)
            .send_min_ack_delay_transport_parameter(local_min_ack)
            .enable_ecn(false)
            .ack_obligation_only(true)
            .reset_finished_on_stop(true)
            .pto_single_probe_with_gap(single_probe)
            .ack_frequency_config(configured_ack_frequency.then(AckFrequencyConfig::default));
        let mut pair = Pair::new(Default::default(), server);
        let (client, server) = pair.connect_with(client);
        assert_eq!(
            pair.client_conn_mut(client).stats().frame_tx.ack_frequency > 0,
            configured_ack_frequency && peer_min_ack
        );
        assert_eq!(
            pair.server_conn_mut(server).stats().frame_rx.ack_frequency > 0,
            configured_ack_frequency && peer_min_ack
        );
        Self {
            pair,
            client,
            server,
            single_probe,
        }
    }

    fn client_output(&mut self, deliver: bool) -> Vec<PacketSummary> {
        let now = self.pair.time;
        for (ecn, bytes) in transmit(self.pair.client_conn_mut(self.client), now) {
            assert_eq!(ecn, None);
            self.pair.server.inbound.push_back((now, ecn, bytes));
        }
        let remote = self.pair.client.addr;
        receive(&mut self.pair.server, remote, self.server, deliver)
    }

    fn server_output(&mut self, deliver: bool) -> Vec<PacketSummary> {
        let now = self.pair.time;
        for (ecn, bytes) in transmit(self.pair.server_conn_mut(self.server), now) {
            self.pair.client.inbound.push_back((now, ecn, bytes));
        }
        let remote = self.pair.server.addr;
        receive(&mut self.pair.client, remote, self.client, deliver)
    }

    fn withhold_peer_ack(&mut self) {
        let mut packets = self.server_output(false);
        if packets.is_empty() {
            let timeout = self
                .pair
                .server_conn_mut(self.server)
                .poll_timeout()
                .unwrap();
            self.pair.time = timeout;
            self.pair
                .server_conn_mut(self.server)
                .handle_timeout(timeout);
            packets = self.server_output(false);
        }
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].types, vec!["ACK"]);
        assert!(!packets[0].ack_eliciting);
    }

    fn reset_with_unacknowledged_packet(&mut self) -> (StreamId, u64) {
        let stream = self.pair.client_streams(self.client).open(Dir::Bi).unwrap();
        self.pair
            .client_send(self.client, stream)
            .write(b"1234567")
            .unwrap();
        self.pair.client_send(self.client, stream).finish().unwrap();
        let sent = self.client_output(true);
        assert_eq!(sent.len(), 1);
        assert!(sent[0].types.contains(&"STREAM"));
        assert_eq!(
            self.pair.server_streams(self.server).accept(Dir::Bi),
            Some(stream)
        );
        self.pair
            .server_recv(self.server, stream)
            .stop(268u32.into())
            .unwrap();
        let stop = self.server_output(true);
        assert_eq!(stop.len(), 1);
        assert!(stop[0].types.contains(&"STOP"));
        let reset = self.client_output(true);
        assert_eq!(reset.len(), 1);
        assert_eq!(reset[0].reset, Some((stream, 268, 7)));
        self.withhold_peer_ack();
        assert_eq!(
            self.pair
                .client_send(self.client, stream)
                .stopped()
                .unwrap(),
            Some(268u32.into())
        );
        (stream, reset[0].number)
    }

    fn fire_client_pto(&mut self) -> Vec<PacketSummary> {
        let timeout = self
            .pair
            .client_conn_mut(self.client)
            .poll_timeout()
            .unwrap();
        assert!(timeout >= self.pair.time);
        self.pair.time = timeout;
        self.pair
            .client_conn_mut(self.client)
            .handle_timeout(timeout);
        let packets = self.client_output(true);
        assert_eq!(
            packets.len(),
            if self.single_probe { 1 } else { 2 },
            "PTO probe count must match the selected policy"
        );
        assert!(packets.iter().all(|packet| packet.ack_eliciting));
        assert!(packets.iter().all(|packet| packet.encrypted_bytes <= 1200));
        if !self.single_probe {
            assert_eq!(packets[1].number, packets[0].number + 1);
        }
        packets
    }

    fn recover(&mut self) {
        self.pair.drive();
        assert_eq!(self.pair.client_conn_mut(self.client).bytes_in_flight(), 0);
        self.pair
            .server_datagrams(self.server)
            .send(Bytes::from_static(b"recovered"), false)
            .unwrap();
        self.pair.drive();
        assert_eq!(
            self.pair.client_datagrams(self.client).recv(),
            Some(Bytes::from_static(b"recovered"))
        );
    }

    fn send_controlled_ack(&mut self, ranges: &[std::ops::RangeInclusive<u64>]) {
        let now = self.pair.time;
        self.pair
            .server_conn_mut(self.server)
            .queue_ack_for_pto_test(now, ranges);
        let received = self.server_output(true);
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].types, vec!["ACK"]);
        let ack = received[0].ack.as_ref().unwrap();
        assert_eq!(ack.iter().collect::<Vec<_>>(), ranges);
    }

    fn assert_gap_protocol_violation(&mut self, stream: StreamId) {
        assert!(std::iter::from_fn(|| self.pair.client_conn_mut(self.client).poll()).any(|event| {
            matches!(event, Event::ConnectionLost { reason: ConnectionError::TransportError(error) }
                if error.code == TransportErrorCode::PROTOCOL_VIOLATION)
        }));
        // Even an ACK containing a real RESET copy must fail before its callback
        // can release the send state.
        assert_eq!(
            self.pair
                .client_send(self.client, stream)
                .stopped()
                .unwrap(),
            Some(268u32.into())
        );
    }
}

#[test]
fn pto_fingerprint_chrome_single_probe_gap_expectation() {
    let mut case = PtoCase::configured(true, false, false, false, true);
    let (stream, reset_pn) = case.reset_with_unacknowledged_packet();
    let packets = case.fire_client_pto();
    eprintln!("Chrome PTO expectation original={reset_pn}: {packets:?}");
    assert_eq!(packets.len(), 1, "Chrome grants one PTO transmission");
    assert_eq!(packets[0].number, reset_pn + 2);
    assert_eq!(packets[0].types, vec!["RESET"]);
    assert_eq!(packets[0].reset, Some((stream, 268, 7)));
    case.recover();
}

#[test]
fn pto_fingerprint_chrome_delayed_poll_does_not_accumulate_probe_budget() {
    let mut case = PtoCase::configured(true, false, false, false, true);
    let (stream, original) = case.reset_with_unacknowledged_packet();
    let timeout = case
        .pair
        .client_conn_mut(case.client)
        .poll_timeout()
        .unwrap();
    case.pair.time = timeout;
    case.pair
        .client_conn_mut(case.client)
        .handle_timeout(timeout);
    let pending = case
        .pair
        .client_conn_mut(case.client)
        .pto_state_for_test(SpaceId::Data);
    assert_eq!(pending, (original + 2, 1, true, 1));
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .loss_timeout_for_pto_test(),
        None
    );
    // Delayed polling must not regenerate a PTO or a second gap. Other timers
    // may still run during this interval.
    case.pair.time += Duration::from_millis(250);
    case.pair
        .client_conn_mut(case.client)
        .handle_timeout(timeout + Duration::from_millis(250));
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .pto_state_for_test(SpaceId::Data),
        pending
    );
    let packets = case.client_output(true);
    eprintln!("delayed PTO flush: {packets:?}");
    assert_eq!(
        packets.len(),
        1,
        "a new PTO replaces the unused transmission opportunity"
    );
    assert_eq!(packets[0].number, original + 2);
    assert_eq!(packets[0].types, vec!["RESET"]);
    assert_eq!(packets[0].reset, Some((stream, 268, 7)));
    assert!(
        case.pair
            .client_conn_mut(case.client)
            .loss_timeout_for_pto_test()
            .is_some()
    );
    case.recover();
}

#[test]
fn pto_fingerprint_chrome_repeated_pto_retains_reset_and_recovers() {
    for peer_min_ack in [false, true] {
        for local_min_ack in [false, true] {
            for configured in [false, true] {
                let mut case =
                    PtoCase::configured(peer_min_ack, local_min_ack, configured, false, true);
                let (stream, mut previous) = case.reset_with_unacknowledged_packet();
                for round in 0..4 {
                    let packets = case.fire_client_pto();
                    assert_eq!(packets.len(), 1);
                    assert_eq!(packets[0].number, previous + 2);
                    assert_eq!(packets[0].types, vec!["RESET"]);
                    assert_eq!(packets[0].reset, Some((stream, 268, 7)));
                    eprintln!(
                        "single PTO peer_min={peer_min_ack} local_min={local_min_ack} config={configured} round={round}: {packets:?}"
                    );
                    previous = packets[0].number;
                    if round != 3 {
                        case.withhold_peer_ack();
                    }
                }
                case.recover();
                assert!(
                    case.pair
                        .client_send(case.client, stream)
                        .stopped()
                        .is_err()
                );
            }
        }
    }
}

#[test]
fn pto_fingerprint_chrome_ack_before_pending_probe_keeps_one_credit_for_ping() {
    let mut case = PtoCase::configured(true, false, false, false, true);
    let (stream, original) = case.reset_with_unacknowledged_packet();
    let timeout = case
        .pair
        .client_conn_mut(case.client)
        .poll_timeout()
        .unwrap();
    case.pair.time = timeout;
    case.pair
        .client_conn_mut(case.client)
        .handle_timeout(timeout);
    case.send_controlled_ack(std::slice::from_ref(&(original..=original)));
    assert!(
        case.pair
            .client_send(case.client, stream)
            .stopped()
            .is_err()
    );
    let pending = case
        .pair
        .client_conn_mut(case.client)
        .pto_state_for_test(SpaceId::Data);
    assert_eq!((pending.0, pending.1), (original + 2, 1));
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .loss_timeout_for_pto_test(),
        None
    );
    let packets = case.client_output(true);
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].number, original + 2);
    assert_eq!(packets[0].types, vec!["PING"]);
    assert!(packets[0].ack_eliciting);
    assert!(
        case.pair
            .client_conn_mut(case.client)
            .loss_timeout_for_pto_test()
            .is_some()
    );
    case.send_controlled_ack(std::slice::from_ref(
        &(packets[0].number..=packets[0].number),
    ));
    assert!(
        !std::iter::from_fn(|| case.pair.client_conn_mut(case.client).poll())
            .any(|event| matches!(event, Event::ConnectionLost { .. }))
    );
    case.recover();
}

#[test]
fn pto_fingerprint_chrome_packetized_probe_can_arm_another_pto_before_delivery() {
    let mut case = PtoCase::configured(true, false, false, false, true);
    let (_, original) = case.reset_with_unacknowledged_packet();
    let timeout = case
        .pair
        .client_conn_mut(case.client)
        .poll_timeout()
        .unwrap();
    case.pair.time = timeout;
    case.pair
        .client_conn_mut(case.client)
        .handle_timeout(timeout);
    // This models an already packetized datagram held outside proto, not an
    // unconsumed probe opportunity.
    let buffered = case.client_output(false);
    assert_eq!(buffered.len(), 1);
    assert_eq!(buffered[0].number, original + 2);
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .pto_state_for_test(SpaceId::Data)
            .1,
        0
    );
    assert!(
        case.pair
            .client_conn_mut(case.client)
            .loss_timeout_for_pto_test()
            .is_some()
    );
    let next = case.fire_client_pto();
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].number, buffered[0].number + 2);
    assert_eq!(next[0].types, vec!["RESET"]);
    case.recover();
}

#[test]
fn pto_fingerprint_chrome_reserved_gap_ack_fails_after_prior_packet_acked() {
    let mut case = PtoCase::configured(true, false, false, false, true);
    let (_, original) = case.reset_with_unacknowledged_packet();
    let timeout = case
        .pair
        .client_conn_mut(case.client)
        .poll_timeout()
        .unwrap();
    case.pair.time = timeout;
    case.pair
        .client_conn_mut(case.client)
        .handle_timeout(timeout);
    case.send_controlled_ack(std::slice::from_ref(&(original..=original)));
    let state = case
        .pair
        .client_conn_mut(case.client)
        .pto_state_for_test(SpaceId::Data);
    eprintln!("reserved-gap original={original} after valid ACK state={state:?}");
    assert_eq!((state.0, state.1), (original + 2, 1));
    case.send_controlled_ack(std::slice::from_ref(&(original + 1..=original + 1)));
    assert!(
        std::iter::from_fn(|| case.pair.client_conn_mut(case.client).poll()).any(|event| {
            matches!(event, Event::ConnectionLost { reason: ConnectionError::TransportError(error) }
            if error.code == TransportErrorCode::PROTOCOL_VIOLATION)
        }),
        "reserved but never packetized gap must not become ACKable"
    );
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .pto_state_for_test(SpaceId::Data)
            .1,
        1
    );
}

#[test]
fn pto_fingerprint_chrome_late_ack_of_lost_real_probe_keeps_monotonic_sent_bound() {
    let mut case = PtoCase::configured(true, false, false, false, true);
    let (_, original) = case.reset_with_unacknowledged_packet();
    let first = case.fire_client_pto()[0].number;
    case.withhold_peer_ack();
    case.fire_client_pto();
    case.withhold_peer_ack();
    let latest = case.fire_client_pto()[0].number;
    assert_eq!((first, latest), (original + 2, original + 6));
    let losses = case
        .pair
        .client_conn_mut(case.client)
        .stats()
        .path
        .lost_packets;
    case.send_controlled_ack(std::slice::from_ref(&(latest..=latest)));
    assert!(
        case.pair
            .client_conn_mut(case.client)
            .stats()
            .path
            .lost_packets
            > losses
    );
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .sent_state_for_pto_test(first),
        (Some(latest), false)
    );
    case.send_controlled_ack(std::slice::from_ref(&(first..=first)));
    assert!(
        !std::iter::from_fn(|| case.pair.client_conn_mut(case.client).poll())
            .any(|event| matches!(event, Event::ConnectionLost { .. }))
    );
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .sent_state_for_pto_test(first)
            .0,
        Some(latest)
    );
    case.recover();
}

#[test]
fn pto_fingerprint_chrome_actual_ack_only_packet_advances_sent_bound() {
    let mut case = PtoCase::configured(true, false, false, false, true);
    for _ in 0..2 {
        case.pair.server_conn_mut(case.server).ping();
        assert!(case.server_output(true)[0].types.contains(&"PING"));
    }
    let packets = case.client_output(true);
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].types, vec!["ACK"]);
    let number = packets[0].number;
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .sent_state_for_pto_test(number),
        (Some(number), true)
    );
    case.send_controlled_ack(std::slice::from_ref(&(number..=number)));
    assert!(
        !std::iter::from_fn(|| case.pair.client_conn_mut(case.client).poll())
            .any(|event| matches!(event, Event::ConnectionLost { .. }))
    );
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .sent_state_for_pto_test(number),
        (Some(number), false)
    );
}

#[test]
fn pto_fingerprint_chrome_no_retransmittable_control_still_probes_with_ping() {
    for peer_min_ack in [false, true] {
        let mut case = PtoCase::configured(peer_min_ack, false, false, false, true);
        case.pair.client_conn_mut(case.client).ping();
        let original = case.client_output(true);
        assert_eq!(original[0].types, vec!["PING"]);
        case.withhold_peer_ack();
        let packets = case.fire_client_pto();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].number, original[0].number + 2);
        assert_eq!(packets[0].types, vec!["PING"]);
        assert!(packets[0].ack_eliciting);
        case.recover();
    }
}

#[test]
fn pto_fingerprint_chrome_preserves_fresh_ack_obligation_and_ecn() {
    for ecn in [false, true] {
        let mut case = PtoCase::configured(true, false, false, ecn, true);
        let (stream, original) = case.reset_with_unacknowledged_packet();
        case.pair.server_conn_mut(case.server).ping();
        let incoming = case.server_output(true);
        assert_eq!(incoming.len(), 1);
        assert!(incoming[0].types.contains(&"PING"));
        let packets = case.fire_client_pto();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].number, original + 2);
        assert_eq!(
            packets[0].types,
            vec![if ecn { "ACK_ECN" } else { "ACK" }, "RESET"]
        );
        assert_eq!(packets[0].reset, Some((stream, 268, 7)));
        assert!(
            packets[0]
                .ack
                .as_ref()
                .unwrap()
                .iter()
                .any(|range| range.contains(&incoming[0].number))
        );
        case.recover();
    }
}

#[test]
fn pto_fingerprint_chrome_authenticated_gap_acks_fail_before_reset_release() {
    for target in [0, 1, 2] {
        let mut case = PtoCase::configured(true, false, false, false, true);
        let (stream, original) = case.reset_with_unacknowledged_packet();
        let first = case.fire_client_pto()[0].number;
        case.withhold_peer_ack();
        let second = case.fire_client_pto()[0].number;
        assert_eq!((first, second), (original + 2, original + 4));
        assert_eq!(
            case.pair
                .client_conn_mut(case.client)
                .pto_state_for_test(SpaceId::Data)
                .3,
            2
        );
        let range = match target {
            0 => first - 1..=first - 1,
            1 => second - 1..=second - 1,
            _ => original..=second,
        };
        case.send_controlled_ack(&[range]);
        case.assert_gap_protocol_violation(stream);
    }
}

#[test]
fn pto_fingerprint_chrome_retires_old_gaps_but_protects_new_gaps() {
    let mut case = PtoCase::configured(true, false, false, false, true);
    let (_, original) = case.reset_with_unacknowledged_packet();
    let first = case.fire_client_pto()[0].number;
    assert_eq!(first, original + 2);
    case.recover();
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .pto_state_for_test(SpaceId::Data)
            .3,
        0
    );
    // The real valid ACK has advanced the floor; this old gap-only ACK now has
    // no newly acknowledged packet and must not close the connection.
    case.send_controlled_ack(std::slice::from_ref(&(first - 1..=first - 1)));
    assert!(
        !std::iter::from_fn(|| case.pair.client_conn_mut(case.client).poll())
            .any(|event| matches!(event, Event::ConnectionLost { .. }))
    );
    case.pair.client_conn_mut(case.client).ping();
    let new_ping = case.client_output(true);
    assert_eq!(new_ping.len(), 1);
    assert_eq!(new_ping[0].types, vec!["PING"]);
    case.withhold_peer_ack();
    let newest = case.fire_client_pto()[0].number;
    case.send_controlled_ack(&[newest - 1..=newest, first - 1..=first - 1]);
    assert!(
        std::iter::from_fn(|| case.pair.client_conn_mut(case.client).poll()).any(|event| {
            matches!(event, Event::ConnectionLost { reason: ConnectionError::TransportError(error) }
            if error.code == TransportErrorCode::PROTOCOL_VIOLATION)
        })
    );
}

#[test]
fn pto_fingerprint_chrome_preserves_preexisting_immediate_ack_request() {
    let mut case = PtoCase::configured(true, false, false, false, true);
    let (stream, original) = case.reset_with_unacknowledged_packet();
    case.pair
        .client_conn_mut(case.client)
        .request_immediate_ack_for_pto_test();
    let packets = case.fire_client_pto();
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].number, original + 2);
    assert_eq!(packets[0].types, vec!["IMMEDIATE_ACK", "RESET"]);
    assert_eq!(packets[0].reset, Some((stream, 268, 7)));
    case.recover();
}

fn client_with_pto_mode(enabled: bool) -> ClientConfig {
    let mut config = client_config_with_deterministic_pns();
    Arc::get_mut(&mut config.transport)
        .unwrap()
        .pto_single_probe_with_gap(enabled)
        .mtu_discovery_config(None);
    config
}

#[test]
fn pto_fingerprint_initial_and_handshake_probes_preserve_legacy_budget_and_numbers() {
    for enabled in [false, true] {
        for handshake in [false, true] {
            let mut pair = Pair::default_with_deterministic_pns();
            let client = pair.begin_connect(client_with_pto_mode(enabled));
            pair.drive_client();
            if handshake {
                pair.drive_server();
                pair.drive_client();
            }
            let space = if handshake {
                SpaceId::Handshake
            } else {
                SpaceId::Initial
            };
            let before = pair.client_conn_mut(client).pto_state_for_test(space);
            assert!(
                before.0 > 0,
                "real encrypted handshake traffic must have been sent"
            );
            assert!(!before.2);
            assert_eq!(before.3, 0);
            let timeout = pair.client_conn_mut(client).poll_timeout().unwrap();
            pair.time = timeout;
            pair.client_conn_mut(client).handle_timeout(timeout);
            let pending = pair.client_conn_mut(client).pto_state_for_test(space);
            assert_eq!(pending.0, before.0, "no intentional gap at this PTO");
            assert_eq!(pending.1, 2);
            assert_eq!(pending.3, 0);
            let packets = transmit(pair.client_conn_mut(client), timeout);
            assert_eq!(packets.len(), 2);
            assert_eq!(
                pair.client_conn_mut(client).pto_state_for_test(space).0,
                before.0 + 2
            );
            for (ecn, bytes) in packets {
                assert_eq!(bytes[0] & 0xb0, if handshake { 0xa0 } else { 0x80 });
                pair.server.inbound.push_back((timeout, ecn, bytes));
            }
            pair.drive();
            assert!(
                std::iter::from_fn(|| pair.client_conn_mut(client).poll())
                    .any(|event| matches!(event, Event::Connected))
            );
            assert_eq!(
                pair.client_conn_mut(client)
                    .pto_state_for_test(SpaceId::Data)
                    .3,
                0
            );
        }
    }
}

#[test]
fn pto_fingerprint_actual_zero_rtt_keeps_normal_numbers_and_uses_initial_pto() {
    for enabled in [false, true] {
        let mut pair = Pair::default_with_deterministic_pns();
        let config = client_with_pto_mode(enabled);
        let client = pair.begin_connect(config.clone());
        pair.drive();
        pair.server.assert_accept();
        let now = pair.time;
        pair.client_conn_mut(client)
            .close(now, VarInt(0), Bytes::new());
        pair.drive();
        pair.client
            .addr
            .set_port(CLIENT_PORTS.lock().unwrap().next().unwrap());
        let client = pair.begin_connect(config);
        assert!(pair.client_conn_mut(client).has_0rtt());
        pair.drive_client();
        pair.drive_server();
        let server = pair.server.assert_accept();
        // Hold the encrypted server flight so this stream is truly 0-RTT.
        let before = pair
            .client_conn_mut(client)
            .pto_state_for_test(SpaceId::Data);
        assert_eq!(before, (0, 0, false, 0));
        let stream = pair.client_streams(client).open(Dir::Bi).unwrap();
        pair.client_send(client, stream)
            .write(b"early request")
            .unwrap();
        let now = pair.time;
        let outgoing = transmit(pair.client_conn_mut(client), now);
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].1[0] & 0xb0, 0x90);
        for (ecn, bytes) in outgoing {
            pair.server.inbound.push_back((now, ecn, bytes));
        }
        let remote = pair.client.addr;
        let early = receive(&mut pair.server, remote, server, true);
        assert_eq!(early.len(), 1);
        assert_eq!(early[0].number, 0);
        assert_eq!(early[0].types, vec!["STREAM"]);
        let timeout = pair.client_conn_mut(client).poll_timeout().unwrap();
        pair.time = timeout;
        pair.client_conn_mut(client).handle_timeout(timeout);
        assert_eq!(
            pair.client_conn_mut(client)
                .pto_state_for_test(SpaceId::Data),
            (1, 0, false, 0)
        );
        assert_eq!(
            pair.client_conn_mut(client)
                .pto_state_for_test(SpaceId::Initial)
                .1,
            2
        );
        pair.drive();
        assert!(pair.client_conn_mut(client).accepted_0rtt());
        assert_eq!(
            stream_chunks(pair.server_recv(server, stream)),
            b"early request"
        );
    }
}

#[test]
fn pto_fingerprint_reset_probe_depends_on_peer_min_ack_not_local_advertisement_or_config() {
    for peer_min_ack in [false, true] {
        for local_min_ack in [false, true] {
            for configured_ack_frequency in [false, true] {
                let mut case =
                    PtoCase::new(peer_min_ack, local_min_ack, configured_ack_frequency, false);
                let (stream, reset_pn) = case.reset_with_unacknowledged_packet();
                let before = case.pair.client_conn_mut(case.client).stats();
                let packets = case.fire_client_pto();
                assert_eq!(
                    packets[0].number,
                    reset_pn + 1,
                    "deterministic PN mode exposes no PTO-specific skip"
                );
                eprintln!(
                    "RESET PTO peer_min_ack={peer_min_ack} local_min_ack={local_min_ack} configured={configured_ack_frequency}: {packets:?}"
                );
                let expected = if peer_min_ack {
                    vec!["IMMEDIATE_ACK", "RESET"]
                } else {
                    vec!["RESET"]
                };
                for packet in packets {
                    assert_eq!(packet.types, expected);
                    assert_eq!(packet.reset, Some((stream, 268, 7)));
                }
                let after = case.pair.client_conn_mut(case.client).stats();
                assert_eq!(
                    after.frame_tx.reset_stream - before.frame_tx.reset_stream,
                    2
                );
                assert_eq!(
                    after.frame_tx.immediate_ack - before.frame_tx.immediate_ack,
                    if peer_min_ack { 2 } else { 0 }
                );
                case.recover();
                assert!(
                    case.pair
                        .client_send(case.client, stream)
                        .stopped()
                        .is_err()
                );
            }
        }
    }
}

#[test]
fn pto_fingerprint_without_retransmittable_control_uses_ping_or_immediate_ack() {
    for peer_min_ack in [false, true] {
        let mut case = PtoCase::new(peer_min_ack, false, false, false);
        case.pair.client_conn_mut(case.client).ping();
        let sent = case.client_output(true);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].types, vec!["PING"]);
        case.withhold_peer_ack();
        let packets = case.fire_client_pto();
        assert_eq!(packets[0].number, sent[0].number + 1);
        eprintln!("bare PTO peer_min_ack={peer_min_ack}: {packets:?}");
        for packet in packets {
            assert_eq!(
                packet.types,
                if peer_min_ack {
                    vec!["IMMEDIATE_ACK"]
                } else {
                    vec!["PING"]
                }
            );
            assert!(packet.reset.is_none());
        }
        case.recover();
    }
}

#[test]
fn pto_fingerprint_lost_ack_gap_keeps_ack_and_ecn_before_reset_retransmission() {
    for peer_ecn in [false, true] {
        for pings in [1, 2] {
            let mut case = PtoCase::new(true, false, false, peer_ecn);
            let (stream, reset_pn) = case.reset_with_unacknowledged_packet();
            for _ in 0..pings {
                case.pair.server_conn_mut(case.server).ping();
                let incoming = case.server_output(true);
                assert_eq!(incoming.len(), 1);
                assert!(incoming[0].types.contains(&"PING"));
            }
            let packets = case.fire_client_pto();
            assert_eq!(packets[0].number, reset_pn + 1);
            let ack = if peer_ecn { "ACK_ECN" } else { "ACK" };
            // The withheld ACK leaves a real peer PN gap, so even one PING
            // requires an immediate ACK rather than a delayed bundled ACK.
            assert_eq!(packets[0].types, vec!["IMMEDIATE_ACK", ack, "RESET"]);
            assert_eq!(packets[1].types, vec!["IMMEDIATE_ACK", "RESET"]);
            assert!(
                packets
                    .iter()
                    .all(|packet| packet.reset == Some((stream, 268, 7)))
            );
            eprintln!("PTO composition peer_ecn={peer_ecn} fresh_pings={pings}: {packets:?}");
            case.recover();
        }
    }
}
