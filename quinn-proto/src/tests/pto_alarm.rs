use super::*;
use crate::connection::PtoTimingSnapshot;
use crate::packet::SpaceId;

struct AlarmCase {
    pair: Pair,
    client: ConnectionHandle,
    server: ConnectionHandle,
}

fn transmit_one(connection: &mut Connection, now: Instant) -> (Option<EcnCodepoint>, BytesMut) {
    let mut bytes = Vec::new();
    let sent = connection
        .poll_transmit(now, 1, &mut bytes)
        .expect("an actual packet must be available at the controlled send time");
    assert!(sent.segment_size.is_none());
    (sent.ecn, BytesMut::from(&bytes[..sent.size]))
}

fn receive(
    endpoint: &mut TestEndpoint,
    remote: SocketAddr,
    handle: ConnectionHandle,
    now: Instant,
    packet: (Option<EcnCodepoint>, BytesMut),
) -> (u64, Vec<Frame>) {
    let Some(DatagramEvent::ConnectionEvent(actual, event)) =
        endpoint.handle(now, remote, None, packet.0, packet.1, &mut Vec::new())
    else {
        panic!("expected an established authenticated peer packet");
    };
    assert_eq!(actual, handle);
    let connection = endpoint.connections.get_mut(&handle).unwrap();
    let (number, payload) = connection.decode_packet_with_number(&event).unwrap();
    let frames = frame::Iter::new(payload.into())
        .unwrap()
        .map(Result::unwrap)
        .filter(|frame| !matches!(frame, Frame::Padding))
        .collect();
    connection.handle_event(event);
    (number.unwrap(), frames)
}

impl AlarmCase {
    fn new(chrome_timing: bool) -> Self {
        Self::with_latency(chrome_timing, Duration::from_millis(50))
    }

    fn with_latency(chrome_timing: bool, one_way: Duration) -> Self {
        Self::configured(chrome_timing, one_way, None)
    }

    fn configured(chrome_timing: bool, one_way: Duration, time_threshold: Option<f32>) -> Self {
        let mut server = server_config();
        let mut transport = TransportConfig::default();
        transport
            .deterministic_packet_numbers(true)
            .mtu_discovery_config(None)
            .enable_ecn(false)
            .send_min_ack_delay_transport_parameter(false)
            .ack_obligation_only(true);
        server.transport_config(Arc::new(transport));
        let mut client = client_config_with_deterministic_pns();
        Arc::get_mut(&mut client.transport)
            .unwrap()
            .mtu_discovery_config(None)
            .enable_ecn(false)
            .send_min_ack_delay_transport_parameter(false)
            .ack_obligation_only(true)
            .pto_single_probe_with_gap(true)
            .chrome_pto_timing(chrome_timing)
            .chrome_loss_timing(chrome_timing)
            .chrome_rtt_quantization(true);
        if let Some(threshold) = time_threshold {
            Arc::get_mut(&mut client.transport)
                .unwrap()
                .time_threshold(threshold);
        }
        let mut pair = Pair::new(Default::default(), server);
        pair.latency = one_way;
        let (client, server) = pair.connect_with(client);
        let mut result = Self {
            pair,
            client,
            server,
        };
        // Train only through actual encrypted PING/ACK traffic. Two PINGs
        // elicit an immediate peer ACK with two controlled one-way delays.
        for _ in 0..16 {
            result.rtt_sample();
        }
        let state = result.snapshot();
        assert!(state.confirmed && state.sampled && state.has_data_keys);
        assert_eq!(state.backoff, 0);
        assert!(state.deadline.is_none());
        assert_eq!(result.pair.client_conn_mut(client).bytes_in_flight(), 0);
        result
    }

    fn snapshot(&mut self) -> PtoTimingSnapshot {
        self.pair.client_conn_mut(self.client).pto_timing_for_test()
    }

    fn ping(&mut self) -> (Option<EcnCodepoint>, BytesMut) {
        let now = self.pair.time;
        let connection = self.pair.client_conn_mut(self.client);
        connection.ping();
        transmit_one(connection, now)
    }

    fn commit_ping(&mut self) -> u64 {
        let packet = self.ping();
        let now = self.pair.time;
        let (number, frames) = receive(
            &mut self.pair.server,
            self.pair.client.addr,
            self.server,
            now,
            packet,
        );
        assert!(frames.iter().any(|frame| matches!(frame, Frame::Ping)));
        number
    }

    fn peer_ack(
        &mut self,
        ranges: &[std::ops::RangeInclusive<u64>],
    ) -> (Option<EcnCodepoint>, BytesMut) {
        let now = self.pair.time;
        let connection = self.pair.server_conn_mut(self.server);
        connection.queue_ack_for_pto_test(now, ranges);
        transmit_one(connection, now)
    }

    fn accept_ack(
        &mut self,
        packet: (Option<EcnCodepoint>, BytesMut),
        ranges: &[std::ops::RangeInclusive<u64>],
    ) {
        let now = self.pair.time;
        let (_, frames) = receive(
            &mut self.pair.client,
            self.pair.server.addr,
            self.client,
            now,
            packet,
        );
        let ack = frames
            .iter()
            .find_map(|frame| match frame {
                Frame::Ack(ack) => Some(ack),
                _ => None,
            })
            .expect("the authenticated peer packet must contain the controlled ACK");
        assert_eq!(ack.iter().collect::<Vec<_>>(), ranges);
        assert_eq!(ack.delay, 0);
    }

    fn candidate(&mut self) -> Instant {
        let now = self.pair.time;
        let (deadline, space) = self
            .pair
            .client_conn_mut(self.client)
            .pto_candidate_for_timing_test(now)
            .unwrap();
        assert_eq!(space, SpaceId::Data);
        deadline
    }

    fn rtt_sample(&mut self) {
        let packets = [self.ping(), self.ping()];
        self.pair.time += self.pair.latency;
        let now = self.pair.time;
        for packet in packets {
            let (_, frames) = receive(
                &mut self.pair.server,
                self.pair.client.addr,
                self.server,
                now,
                packet,
            );
            assert!(frames.iter().any(|frame| matches!(frame, Frame::Ping)));
        }
        let ack = transmit_one(self.pair.server_conn_mut(self.server), now);
        self.pair.time += self.pair.latency;
        let now = self.pair.time;
        let (_, frames) = receive(
            &mut self.pair.client,
            self.pair.server.addr,
            self.client,
            now,
            ack,
        );
        assert!(
            frames
                .iter()
                .any(|frame| matches!(frame, Frame::Ack(ack) if ack.delay == 0))
        );
    }
}

fn two_independent_packets(chrome_timing: bool, spacing_us: u64) -> (Instant, Instant, Instant) {
    let mut case = AlarmCase::new(chrome_timing);
    let trained = case.snapshot();
    let quantize = |value: Duration| Duration::from_micros(value.as_micros().try_into().unwrap());
    let srtt = quantize(trained.smoothed);
    let variance = quantize(trained.variance);
    let ack_delay = quantize(trained.max_ack_delay);
    let right_delay =
        srtt + Duration::from_micros(srtt.as_micros().div_ceil(2).try_into().unwrap());
    let first_delay = srtt + (2 * variance).max(Duration::from_millis(1)) + ack_delay;
    assert!(
        right_delay > first_delay,
        "real RTT training must make the first-flight right edge dominate"
    );

    let first_sent = case.pair.time;
    let packet = case.ping();
    let remote = case.pair.client.addr;
    let (first_pn, frames) = receive(
        &mut case.pair.server,
        remote,
        case.server,
        first_sent,
        packet,
    );
    assert!(frames.iter().any(|frame| matches!(frame, Frame::Ping)));
    let first = case.snapshot();
    let armed = first.deadline.unwrap();
    if chrome_timing {
        assert_eq!(armed, first_sent + right_delay);
    } else {
        let legacy = trained.smoothed
            + (4 * trained.variance).max(Duration::from_millis(1))
            + trained.max_ack_delay;
        assert_eq!(armed, first_sent + legacy);
    }

    // No ACK or timeout is delivered to the client between these separate
    // packet commitments. Inspect the first armed deadline before the second.
    case.pair.time += Duration::from_micros(spacing_us);
    let second_sent = case.pair.time;
    let packet = case.ping();
    let (second_pn, frames) = receive(
        &mut case.pair.server,
        remote,
        case.server,
        second_sent,
        packet,
    );
    assert!(second_pn > first_pn);
    assert!(frames.iter().any(|frame| matches!(frame, Frame::Ping)));
    let after = case.snapshot();
    assert_eq!(after.backoff, 0);
    assert_eq!(after.smoothed, trained.smoothed);
    assert_eq!(after.variance, trained.variance);
    assert_eq!(after.first_in_flight, Some(first_sent));
    assert_eq!(after.last_ack_eliciting, Some(second_sent));
    let (requested, space) = case
        .pair
        .client_conn_mut(case.client)
        .pto_candidate_for_timing_test(second_sent)
        .unwrap();
    assert_eq!(space, SpaceId::Data);
    assert_eq!(requested, armed + Duration::from_micros(spacing_us));
    let stored = after.deadline.unwrap();
    eprintln!(
        "PTO alarm chrome_timing={chrome_timing} S_us={} V_us={} A_us={} spacing_us={spacing_us} first_pn={first_pn} second_pn={second_pn} old_us={} requested_us={} stored_us={}",
        trained.smoothed.as_micros(),
        trained.variance.as_micros(),
        trained.max_ack_delay.as_micros(),
        armed.duration_since(first_sent).as_micros(),
        requested.duration_since(first_sent).as_micros(),
        stored.duration_since(first_sent).as_micros(),
    );
    (armed, requested, stored)
}

#[test]
fn pto_alarm_chrome_submillisecond_update_preserves_armed_deadline() {
    let (armed, requested, stored) = two_independent_packets(true, 500);
    assert!(requested > armed);
    assert_eq!(
        stored, armed,
        "exact Chrome Update retains changes strictly below 1 ms"
    );
}

#[test]
fn pto_alarm_chrome_exact_millisecond_update_replaces_armed_deadline() {
    let (armed, requested, stored) = two_independent_packets(true, 1_000);
    assert_eq!(requested - armed, Duration::from_millis(1));
    assert_eq!(stored, requested);
}

#[test]
fn pto_alarm_legacy_submillisecond_update_replaces_armed_deadline() {
    let (armed, requested, stored) = two_independent_packets(false, 500);
    assert_eq!(requested - armed, Duration::from_micros(500));
    assert_eq!(stored, requested);
}

#[test]
fn pto_alarm_chrome_cumulative_updates_compare_with_stored_deadline() {
    let mut case = AlarmCase::new(true);
    let started = case.pair.time;
    case.commit_ping();
    let armed = case.snapshot().deadline.unwrap();
    assert_eq!(armed, case.candidate());
    for (offset, stored_shift) in [(500, 0), (999, 0), (1_000, 1_000)] {
        case.pair.time = started + Duration::from_micros(offset);
        case.commit_ping();
        assert_eq!(case.candidate(), armed + Duration::from_micros(offset));
        assert_eq!(
            case.snapshot().deadline,
            Some(armed + Duration::from_micros(stored_shift))
        );
    }
    assert_eq!(case.snapshot().backoff, 0);
}

#[test]
fn pto_alarm_chrome_partial_ack_retains_earlier_and_later_small_updates() {
    for rtt_us in [99_600, 100_400] {
        let mut case = AlarmCase::new(true);
        let started = case.pair.time;
        let first = case.commit_ping();
        let range = first..=first;
        let ack = case.peer_ack(std::slice::from_ref(&range));
        // The peer has only seen the first packet when it creates this ACK.
        // Hold the second real client packet in the simulated network.
        let held = case.ping();
        let armed = case.snapshot().deadline.unwrap();
        assert_eq!(armed - started, Duration::from_millis(150));
        case.pair.time = started + Duration::from_micros(rtt_us);
        case.accept_ack(ack, std::slice::from_ref(&range));
        let requested = case.candidate();
        if rtt_us < 100_000 {
            assert_eq!(armed - requested, Duration::from_micros(75));
        } else {
            assert_eq!(requested - armed, Duration::from_micros(75));
        }
        let after = case.snapshot();
        assert_eq!(after.backoff, 0);
        assert_eq!(after.deadline, Some(armed));
        assert!(case.pair.client_conn_mut(case.client).bytes_in_flight() > 0);
        let now = case.pair.time;
        let (second, frames) = receive(
            &mut case.pair.server,
            case.pair.client.addr,
            case.server,
            now,
            held,
        );
        assert!(second > first);
        assert!(frames.iter().any(|frame| matches!(frame, Frame::Ping)));
        assert!(
            case.pair
                .client_conn_mut(case.client)
                .sent_state_for_pto_test(second)
                .1
        );
        eprintln!(
            "PTO ACK update raw_rtt_us={rtt_us} S_us={} V_us={} old_us={} requested_us={} stored_us={}",
            after.smoothed.as_micros(),
            after.variance.as_micros(),
            (armed - started).as_micros(),
            (requested - started).as_micros(),
            (after.deadline.unwrap() - started).as_micros(),
        );
    }
}

#[test]
fn pto_alarm_chrome_all_acked_cancels_before_a_new_flight() {
    let mut case = AlarmCase::new(true);
    let started = case.pair.time;
    let first = case.commit_ping();
    let second = case.commit_ping();
    let armed = case.snapshot().deadline.unwrap();
    let range = first..=second;
    let ack = case.peer_ack(std::slice::from_ref(&range));
    case.pair.time = started + Duration::from_millis(100);
    case.accept_ack(ack, std::slice::from_ref(&range));
    assert!(case.snapshot().deadline.is_none());
    assert_eq!(case.pair.client_conn_mut(case.client).bytes_in_flight(), 0);
    case.pair.time += Duration::from_micros(500);
    let sent = case.pair.time;
    case.commit_ping();
    let after = case.snapshot();
    assert_eq!(after.first_in_flight, Some(sent));
    assert_eq!(after.deadline, Some(case.candidate()));
    assert_eq!(after.deadline.unwrap() - sent, Duration::from_millis(150));
    assert!(after.deadline.unwrap() > armed);
}

#[test]
fn pto_alarm_chrome_fired_probe_credit_cancels_then_packet_commit_rearms() {
    let mut case = AlarmCase::new(true);
    case.commit_ping();
    let deadline = case.snapshot().deadline.unwrap();
    case.pair.time = deadline;
    case.pair
        .client_conn_mut(case.client)
        .handle_timeout(deadline);
    assert_eq!(case.snapshot().backoff, 1);
    assert!(case.snapshot().deadline.is_none());
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .pto_state_for_test(SpaceId::Data)
            .1,
        1
    );
    case.pair.time += Duration::from_micros(500);
    let now = case.pair.time;
    case.pair.client_conn_mut(case.client).handle_timeout(now);
    assert_eq!(case.snapshot().backoff, 1);
    assert!(case.snapshot().deadline.is_none());
    let probe = transmit_one(case.pair.client_conn_mut(case.client), now);
    let (_, frames) = receive(
        &mut case.pair.server,
        case.pair.client.addr,
        case.server,
        now,
        probe,
    );
    assert!(frames.iter().any(|frame| matches!(frame, Frame::Ping)));
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .pto_state_for_test(SpaceId::Data)
            .1,
        0
    );
    let after = case.snapshot();
    assert_eq!(after.backoff, 1);
    assert_eq!(after.last_ack_eliciting, Some(now));
    assert_eq!(after.deadline, Some(case.candidate()));
    assert_eq!(after.deadline.unwrap() - now, Duration::from_millis(252));
}

#[test]
fn pto_alarm_chrome_expired_unfired_deadline_survives_delayed_ack_update() {
    let mut case = AlarmCase::with_latency(true, Duration::from_millis(20));
    let trained = case.snapshot();
    assert_eq!(trained.smoothed, Duration::from_millis(40));
    assert!(trained.variance * 2 < Duration::from_millis(1));
    assert_eq!(trained.max_ack_delay, Duration::from_millis(25));
    let started = case.pair.time;
    let first_packet = case.ping();
    let held_second = case.ping();
    let armed = case.snapshot().deadline.unwrap();
    assert_eq!(armed - started, Duration::from_millis(66));

    case.pair.time = started + Duration::from_micros(20_550);
    let received_at = case.pair.time;
    let (first, frames) = receive(
        &mut case.pair.server,
        case.pair.client.addr,
        case.server,
        received_at,
        first_packet,
    );
    assert!(frames.iter().any(|frame| matches!(frame, Frame::Ping)));
    assert!(
        case.pair
            .server_conn_mut(case.server)
            .poll_transmit(received_at, 1, &mut Vec::new())
            .is_none(),
        "one ordinary PING must leave the peer's real delayed ACK pending"
    );
    let ack_ready = received_at + Duration::from_millis(25);
    assert_eq!(
        case.pair.server_conn_mut(case.server).poll_timeout(),
        Some(ack_ready)
    );
    case.pair.time = ack_ready;
    case.pair
        .server_conn_mut(case.server)
        .handle_timeout(ack_ready);
    let ack_packet = transmit_one(case.pair.server_conn_mut(case.server), ack_ready);

    // The client's timer is due, but its callback has not run. Deliver a real
    // peer ACK first, as can happen when incoming work precedes timer dispatch.
    case.pair.time += Duration::from_micros(20_550);
    let now = case.pair.time;
    assert_eq!(now - started, Duration::from_micros(66_100));
    assert_eq!(now - armed, Duration::from_micros(100));
    let (_, frames) = receive(
        &mut case.pair.client,
        case.pair.server.addr,
        case.client,
        now,
        ack_packet,
    );
    let ack = frames
        .iter()
        .find_map(|frame| match frame {
            Frame::Ack(ack) => Some(ack),
            _ => None,
        })
        .expect("the actual delayed-ACK timer must produce an ACK");
    assert_eq!(ack.largest, first);
    // Both fixtures use the default negotiated ACK-delay exponent of three.
    assert_eq!(ack.delay, 25_000 >> 3);
    let after = case.snapshot();
    assert_eq!(after.backoff, 0);
    assert_eq!(after.smoothed, Duration::from_micros(40_138));
    assert!(after.variance * 2 < Duration::from_millis(1));
    let requested = case.candidate();
    assert_eq!(requested - started, Duration::from_micros(66_138));
    assert!(requested > now);
    assert_eq!(after.deadline, Some(armed));

    let (second, frames) = receive(
        &mut case.pair.server,
        case.pair.client.addr,
        case.server,
        now,
        held_second,
    );
    assert!(second > first);
    assert!(frames.iter().any(|frame| matches!(frame, Frame::Ping)));
    assert!(
        case.pair
            .client_conn_mut(case.client)
            .sent_state_for_pto_test(second)
            .1
    );
    case.pair.client_conn_mut(case.client).handle_timeout(now);
    assert_eq!(case.snapshot().backoff, 1);
    assert!(case.snapshot().deadline.is_none());
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .pto_state_for_test(SpaceId::Data)
            .1,
        1
    );
    eprintln!(
        "PTO expired slot raw_rtt_us=66100 peer_ack_delay_us=25000 S_us={} V_us={} old_us={} receive_us={} requested_us={} stored_us={} actual_fired_backoff=1",
        after.smoothed.as_micros(),
        after.variance.as_micros(),
        (armed - started).as_micros(),
        (now - started).as_micros(),
        (requested - started).as_micros(),
        (after.deadline.unwrap() - started).as_micros(),
    );
}

struct LossTransition {
    case: AlarmCase,
    low: u64,
    armed: Instant,
    candidate: Instant,
    lost_before: u64,
}

impl LossTransition {
    fn new(chrome_timing: bool, raw_rtt_us: u64) -> Self {
        // Match the pinned source's initial loss shift of two explicitly.
        // Ordinary AlarmCase construction keeps the native default of 9/8.
        let mut case = AlarmCase::configured(chrome_timing, Duration::from_millis(50), Some(1.25));
        let trained = case.snapshot();
        assert_eq!(trained.smoothed, Duration::from_millis(100));
        assert_eq!(trained.max_ack_delay, Duration::from_millis(25));
        assert!(trained.variance * 2 < Duration::from_millis(1));
        let started = case.pair.time;
        let low = case.commit_ping();
        let high = case.commit_ping();
        assert_eq!(
            high,
            low + 1,
            "one missing packet is below the packet loss threshold"
        );
        let armed = case.snapshot().deadline.unwrap();
        if chrome_timing {
            assert_eq!(armed - started, Duration::from_millis(150));
        }
        let range = high..=high;
        let ack = case.peer_ack(std::slice::from_ref(&range));
        let lost_before = case
            .pair
            .client_conn_mut(case.client)
            .stats()
            .path
            .lost_packets;
        // The peer emitted this zero-delay ACK at t0. Delay the authenticated
        // datagram in the simulated network, not in the peer's ACK generator.
        case.pair.time = started + Duration::from_micros(raw_rtt_us);
        case.accept_ack(ack, std::slice::from_ref(&range));
        let after = case.snapshot();
        assert_eq!(after.backoff, 0);
        assert!(after.smoothed < Duration::from_micros(raw_rtt_us));
        assert!(
            case.pair
                .client_conn_mut(case.client)
                .sent_state_for_pto_test(low)
                .1
        );
        assert!(
            !case
                .pair
                .client_conn_mut(case.client)
                .sent_state_for_pto_test(high)
                .1
        );
        assert_eq!(
            case.pair
                .client_conn_mut(case.client)
                .stats()
                .path
                .lost_packets,
            lost_before
        );
        let (candidate, space) = case
            .pair
            .client_conn_mut(case.client)
            .loss_candidate_for_alarm_test()
            .expect("the real high ACK must schedule time-threshold loss of the low packet");
        assert_eq!(space, SpaceId::Data);
        let source_delay_us = raw_rtt_us + raw_rtt_us / 4;
        let actual_delay = candidate - started;
        assert_eq!(
            actual_delay,
            Duration::from_micros(raw_rtt_us).mul_f32(1.25)
        );
        assert_eq!(actual_delay.as_micros(), u128::from(source_delay_us));
        assert!(candidate > case.pair.time);
        let hypothetical_pto = case.candidate();
        if chrome_timing {
            assert!(candidate < hypothetical_pto);
        }
        eprintln!(
            "LOSS alarm chrome_timing={chrome_timing} threshold=1.25 raw_rtt_us={raw_rtt_us} low_pn={low} high_pn={high} S_us={} old_us={} candidate_us={} candidate_sub_us_ns={} hypothetical_pto_us={} stored_us={} k={}",
            after.smoothed.as_micros(),
            (armed - started).as_micros(),
            actual_delay.as_micros(),
            actual_delay.as_nanos() % 1_000,
            (hypothetical_pto - started).as_micros(),
            (after.deadline.unwrap() - started).as_micros(),
            after.backoff,
        );
        Self {
            case,
            low,
            armed,
            candidate,
            lost_before,
        }
    }

    fn assert_real_loss(mut self) {
        let deadline = self.case.snapshot().deadline.unwrap();
        self.case.pair.time = deadline;
        self.case
            .pair
            .client_conn_mut(self.case.client)
            .handle_timeout(deadline);
        assert_eq!(
            self.case
                .pair
                .client_conn_mut(self.case.client)
                .stats()
                .path
                .lost_packets,
            self.lost_before + 1
        );
        assert!(
            !self
                .case
                .pair
                .client_conn_mut(self.case.client)
                .sent_state_for_pto_test(self.low)
                .1
        );
        assert_eq!(self.case.snapshot().backoff, 0);
        assert_eq!(
            self.case
                .pair
                .client_conn_mut(self.case.client)
                .pto_state_for_test(SpaceId::Data)
                .1,
            0
        );
    }
}

#[test]
fn pto_alarm_loss_chrome_submillisecond_update_preserves_armed_deadline() {
    let mut transition = LossTransition::new(true, 119_700);
    assert!(transition.armed > transition.candidate);
    assert!(transition.armed - transition.candidate < Duration::from_millis(1));
    assert_eq!(
        transition.case.snapshot().deadline,
        Some(transition.armed),
        "the pinned shared alarm retains the old deadline for a sub-ms LOSS update too"
    );
    transition.assert_real_loss();
}

#[test]
fn pto_alarm_loss_legacy_update_replaces_armed_deadline() {
    let mut transition = LossTransition::new(false, 119_700);
    assert_ne!(transition.armed, transition.candidate);
    assert!(
        transition.candidate > transition.case.candidate(),
        "LOSS priority must hold even when its deadline is later than hypothetical PTO"
    );
    assert_eq!(
        transition.case.snapshot().deadline,
        Some(transition.candidate)
    );
    transition.assert_real_loss();
}

#[test]
fn pto_alarm_loss_chrome_larger_update_replaces_and_fires_loss_not_pto() {
    let mut transition = LossTransition::new(true, 118_400);
    assert!(transition.armed - transition.candidate >= Duration::from_millis(1));
    assert_eq!(
        transition.case.snapshot().deadline,
        Some(transition.candidate)
    );
    transition.assert_real_loss();
}

#[test]
fn pto_alarm_loss_chrome_early_callback_rearms_before_detecting_loss() {
    let mut transition = LossTransition::new(true, 120_300);
    assert_eq!(
        transition.candidate - transition.armed,
        Duration::from_micros(375)
    );
    assert_eq!(transition.case.snapshot().deadline, Some(transition.armed));
    transition.case.pair.time = transition.armed;
    transition
        .case
        .pair
        .client_conn_mut(transition.case.client)
        .handle_timeout(transition.armed);
    assert_eq!(
        transition
            .case
            .pair
            .client_conn_mut(transition.case.client)
            .stats()
            .path
            .lost_packets,
        transition.lost_before,
        "the retained earlier alarm must not declare loss before the actual threshold"
    );
    assert!(
        transition
            .case
            .pair
            .client_conn_mut(transition.case.client)
            .sent_state_for_pto_test(transition.low)
            .1
    );
    assert_eq!(transition.case.snapshot().backoff, 0);
    assert_eq!(
        transition
            .case
            .pair
            .client_conn_mut(transition.case.client)
            .pto_state_for_test(SpaceId::Data)
            .1,
        0
    );
    assert_eq!(
        transition.case.snapshot().deadline,
        Some(transition.candidate)
    );
    assert_eq!(
        transition
            .case
            .pair
            .client_conn_mut(transition.case.client)
            .loss_candidate_for_alarm_test(),
        Some((transition.candidate, SpaceId::Data))
    );
    transition.assert_real_loss();
}

fn assert_chrome_loss_rtt_floor(time_threshold: Option<f32>, raw_rtt_us: u64) {
    let mut case = AlarmCase::configured(true, Duration::from_micros(250), time_threshold);
    let trained = case.snapshot();
    assert!(trained.confirmed && trained.sampled && trained.has_data_keys);
    assert_eq!(trained.smoothed, Duration::from_micros(501));
    assert_eq!(trained.backoff, 0);
    let factor = time_threshold.unwrap_or(9.0 / 8.0);
    let source_delay = Duration::from_millis(1).mul_f32(factor);
    let started = case.pair.time;
    let low = case.commit_ping();
    let high = case.commit_ping();
    assert_eq!(
        high,
        low + 1,
        "the ACK gap must stay below packet threshold three"
    );
    assert!(
        case.pair
            .client_conn_mut(case.client)
            .sent_state_for_pto_test(low)
            .1
    );
    assert!(
        case.pair
            .client_conn_mut(case.client)
            .sent_state_for_pto_test(high)
            .1
    );
    let armed = case.snapshot().deadline.unwrap();
    assert!(armed > started + source_delay);
    let lost_before = case
        .pair
        .client_conn_mut(case.client)
        .stats()
        .path
        .lost_packets;
    let range = high..=high;
    let ack = case.peer_ack(std::slice::from_ref(&range));
    case.pair.time = started + Duration::from_micros(raw_rtt_us);
    case.accept_ack(ack, std::slice::from_ref(&range));
    let after = case.snapshot();
    assert!(after.smoothed < Duration::from_millis(1));
    assert!(raw_rtt_us < 1000);
    assert_eq!(after.backoff, 0);
    assert!(
        case.pair
            .client_conn_mut(case.client)
            .sent_state_for_pto_test(low)
            .1
    );
    assert!(
        !case
            .pair
            .client_conn_mut(case.client)
            .sent_state_for_pto_test(high)
            .1
    );
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .stats()
            .path
            .lost_packets,
        lost_before
    );
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .pto_state_for_test(SpaceId::Data)
            .1,
        0
    );
    let (candidate, space) = case
        .pair
        .client_conn_mut(case.client)
        .loss_candidate_for_alarm_test()
        .expect("the real higher ACK must schedule the lower packet's time-threshold loss");
    assert_eq!(space, SpaceId::Data);
    assert!(candidate > case.pair.time);
    assert_eq!(after.deadline, Some(candidate));
    assert!(candidate < case.candidate());
    eprintln!(
        "LOSS floor chrome_policy=true factor={factor} trained_S_us={} raw_rtt_us={raw_rtt_us} S_us={} low_pn={low} high_pn={high} low_retained=true high_removed=true lost_delta=0 old_us={} candidate_us={} stored_us={} source_target_us={} k={}",
        trained.smoothed.as_micros(),
        after.smoothed.as_micros(),
        (armed - started).as_micros(),
        (candidate - started).as_micros(),
        (after.deadline.unwrap() - started).as_micros(),
        source_delay.as_micros(),
        after.backoff,
    );
    assert_eq!(
        candidate - started,
        source_delay,
        "Chrome's loss RTT input is floored before applying the configured time threshold"
    );

    let old_floor = started + Duration::from_millis(1);
    case.pair.time = old_floor;
    case.pair
        .client_conn_mut(case.client)
        .handle_timeout(old_floor);
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .stats()
            .path
            .lost_packets,
        lost_before
    );
    assert!(
        case.pair
            .client_conn_mut(case.client)
            .sent_state_for_pto_test(low)
            .1
    );
    assert_eq!(case.snapshot().deadline, Some(candidate));
    assert_eq!(case.snapshot().backoff, 0);
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .pto_state_for_test(SpaceId::Data)
            .1,
        0
    );
    LossTransition {
        case,
        low,
        armed,
        candidate,
        lost_before,
    }
    .assert_real_loss();
}

#[test]
fn pto_alarm_loss_floor_chrome_initial_factor_uses_floored_rtt_input() {
    assert_chrome_loss_rtt_floor(Some(1.25), 800);
}

#[test]
fn pto_alarm_loss_floor_chrome_native_factor_uses_floored_rtt_input() {
    assert_chrome_loss_rtt_floor(None, 500);
}

#[test]
fn pto_alarm_loss_history_chrome_uses_previous_smoothed_rtt() {
    let mut case = AlarmCase::configured(true, Duration::from_millis(50), Some(1.25));
    let trained = case.snapshot();
    assert!(trained.confirmed && trained.sampled && trained.has_data_keys);
    assert_eq!(trained.smoothed, Duration::from_millis(100));
    assert_eq!(trained.backoff, 0);
    let source_delay = trained.smoothed.mul_f32(1.25);
    assert_eq!(source_delay, Duration::from_micros(125_000));
    let started = case.pair.time;
    let low = case.commit_ping();
    let high = case.commit_ping();
    assert_eq!(
        high,
        low + 1,
        "one lower hole cannot meet packet threshold three"
    );
    let armed = case.snapshot().deadline.unwrap();
    assert_eq!(armed - started, Duration::from_millis(150));
    let lost_before = case
        .pair
        .client_conn_mut(case.client)
        .stats()
        .path
        .lost_packets;
    let range = high..=high;
    let ack = case.peer_ack(std::slice::from_ref(&range));
    let raw_rtt = Duration::from_millis(80);
    case.pair.time = started + raw_rtt;
    case.accept_ack(ack, std::slice::from_ref(&range));
    let after = case.snapshot();
    assert_eq!(after.smoothed, Duration::from_micros(97_500));
    assert_eq!(after.backoff, 0);
    assert!(
        case.pair
            .client_conn_mut(case.client)
            .sent_state_for_pto_test(low)
            .1
    );
    assert!(
        !case
            .pair
            .client_conn_mut(case.client)
            .sent_state_for_pto_test(high)
            .1
    );
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .stats()
            .path
            .lost_packets,
        lost_before
    );
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .pto_state_for_test(SpaceId::Data)
            .1,
        0
    );
    let (candidate, space) = case
        .pair
        .client_conn_mut(case.client)
        .loss_candidate_for_alarm_test()
        .expect("the real higher ACK must schedule time-threshold loss");
    assert_eq!(space, SpaceId::Data);
    assert!(candidate > case.pair.time);
    assert_eq!(after.deadline, Some(candidate));
    assert!(candidate < case.candidate());
    let current_smoothed_delay = after.smoothed.max(raw_rtt).mul_f32(1.25);
    assert_eq!(current_smoothed_delay, Duration::from_micros(121_875));
    eprintln!(
        "LOSS history chrome_policy=true factor=1.25 trained_S_us={} raw_rtt_us={} ack_delay_us=0 current_S_us={} low_pn={low} high_pn={high} low_retained=true high_removed=true lost_delta=0 old_us={} candidate_us={} stored_us={} source_target_us={} current_smoothed_target_us={} k={}",
        trained.smoothed.as_micros(),
        raw_rtt.as_micros(),
        after.smoothed.as_micros(),
        (armed - started).as_micros(),
        (candidate - started).as_micros(),
        (after.deadline.unwrap() - started).as_micros(),
        source_delay.as_micros(),
        current_smoothed_delay.as_micros(),
        after.backoff,
    );
    assert_eq!(
        candidate - started,
        source_delay,
        "Chrome loss uses the smoothed RTT from before this actual decreasing sample"
    );

    let earlier = started + current_smoothed_delay;
    case.pair.time = earlier;
    case.pair
        .client_conn_mut(case.client)
        .handle_timeout(earlier);
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .stats()
            .path
            .lost_packets,
        lost_before
    );
    assert!(
        case.pair
            .client_conn_mut(case.client)
            .sent_state_for_pto_test(low)
            .1
    );
    assert_eq!(case.snapshot().deadline, Some(candidate));
    assert_eq!(case.snapshot().backoff, 0);
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .pto_state_for_test(SpaceId::Data)
            .1,
        0
    );
    LossTransition {
        case,
        low,
        armed,
        candidate,
        lost_before,
    }
    .assert_real_loss();
}

fn check_loss_input_control(
    chrome: bool,
    training_rtt_us: u64,
    raw_rtt_us: u64,
    ack_delay_us: u64,
    factor: f32,
    expected_us: u64,
) {
    assert_eq!(training_rtt_us % 2, 0);
    let mut case = AlarmCase::configured(
        chrome,
        Duration::from_micros(training_rtt_us / 2),
        Some(factor),
    );
    let trained = case.snapshot();
    assert!(trained.confirmed && trained.sampled && trained.has_data_keys);
    assert_eq!(trained.backoff, 0);
    let started = case.pair.time;
    let low = case.commit_ping();
    let high = case.commit_ping();
    assert_eq!(high, low + 1);
    let armed = case.snapshot().deadline.unwrap();
    let lost_before = case
        .pair
        .client_conn_mut(case.client)
        .stats()
        .path
        .lost_packets;
    let range = high..=high;
    case.pair
        .server_conn_mut(case.server)
        .queue_ack_for_pto_test(started, std::slice::from_ref(&range));
    // The ACK delay is produced by actual peer time between receipt and send.
    // Only network delivery is withheld after serialization.
    case.pair.time = started + Duration::from_micros(ack_delay_us);
    let ack_sent_at = case.pair.time;
    let ack = transmit_one(case.pair.server_conn_mut(case.server), ack_sent_at);
    assert!(raw_rtt_us >= ack_delay_us);
    case.pair.time = started + Duration::from_micros(raw_rtt_us);
    let received_at = case.pair.time;
    let remote = case.pair.server.addr;
    let (_, frames) = receive(&mut case.pair.client, remote, case.client, received_at, ack);
    let decoded = frames
        .iter()
        .find_map(|frame| match frame {
            Frame::Ack(ack) => Some(ack),
            _ => None,
        })
        .expect("the real higher ACK must be present");
    assert_eq!(decoded.iter().collect::<Vec<_>>(), [range]);
    assert_eq!(decoded.delay * 8, ack_delay_us);
    let after = case.snapshot();
    assert_eq!(after.backoff, 0);
    assert!(
        case.pair
            .client_conn_mut(case.client)
            .sent_state_for_pto_test(low)
            .1
    );
    assert!(
        !case
            .pair
            .client_conn_mut(case.client)
            .sent_state_for_pto_test(high)
            .1
    );
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .stats()
            .path
            .lost_packets,
        lost_before
    );
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .pto_state_for_test(SpaceId::Data)
            .1,
        0
    );
    let (candidate, space) = case
        .pair
        .client_conn_mut(case.client)
        .loss_candidate_for_alarm_test()
        .expect("the lower retained packet must have a time-threshold candidate");
    assert_eq!(space, SpaceId::Data);
    assert!(candidate > case.pair.time);
    assert_eq!(candidate - started, Duration::from_micros(expected_us));
    assert_eq!(after.deadline, Some(candidate));
    if ack_delay_us != 0 {
        assert_eq!(trained.smoothed, Duration::from_millis(100));
        assert_eq!(after.smoothed, Duration::from_millis(100));
    }
    eprintln!(
        "LOSS input control chrome={chrome} factor={factor} trained_S_us={} raw_rtt_us={raw_rtt_us} ack_delay_us={ack_delay_us} S_us={} low_pn={low} high_pn={high} candidate_us={} expected_us={expected_us} k={}",
        trained.smoothed.as_micros(),
        after.smoothed.as_micros(),
        (candidate - started).as_micros(),
        after.backoff,
    );
    LossTransition {
        case,
        low,
        armed,
        candidate,
        lost_before,
    }
    .assert_real_loss();
}

#[test]
fn pto_alarm_loss_input_legacy_low_rtt_preserves_post_multiplier_floor() {
    check_loss_input_control(false, 500, 800, 0, 1.25, 1000);
    check_loss_input_control(false, 500, 500, 0, 9.0 / 8.0, 1000);
}

#[test]
fn pto_alarm_loss_input_at_and_above_floor_preserves_real_candidates() {
    for chrome in [false, true] {
        check_loss_input_control(chrome, 1000, 1000, 0, 1.25, 1250);
        check_loss_input_control(chrome, 2000, 4000, 0, 1.25, 5000);
    }
}

#[test]
fn pto_alarm_loss_input_legacy_decreasing_rtt_uses_current_smoothed_value() {
    check_loss_input_control(false, 100_000, 80_000, 0, 1.25, 121_875);
}

#[test]
fn pto_alarm_loss_input_chrome_uses_actual_peer_ack_adjusted_sample() {
    check_loss_input_control(true, 100_000, 120_000, 20_000, 1.25, 125_000);
    check_loss_input_control(false, 100_000, 120_000, 20_000, 1.25, 150_000);
}

fn check_loss_estimator_history(quantized: bool) {
    let mut first =
        crate::RttEstimator::new(Duration::from_millis(100)).with_chrome_quantization(quantized);
    assert!(first.sampled_rtt_inputs().is_none());
    assert_eq!(first.chrome_loss_rtt(), Duration::from_millis(1));
    first.update(Duration::from_millis(20), Duration::from_millis(150));
    assert_eq!(first.get(), Duration::from_millis(150));
    assert_eq!(first.min(), Duration::from_millis(150));
    assert_eq!(first.conservative(), Duration::from_millis(150));
    eprintln!(
        "LOSS estimator quantized={quantized} first_raw_us=150000 first_ack_us=20000 initial_us=100000 actual_loss_rtt_us={} expected_loss_rtt_us=150000",
        first.chrome_loss_rtt().as_micros(),
    );
    assert_eq!(
        first.chrome_loss_rtt(),
        Duration::from_millis(150),
        "the first real sample establishes minimum RTT before any ACK-delay subtraction"
    );

    let mut estimator =
        crate::RttEstimator::new(Duration::from_millis(333)).with_chrome_quantization(quantized);
    estimator.update(Duration::ZERO, Duration::from_millis(100));
    assert_eq!(estimator.chrome_loss_rtt(), Duration::from_millis(100));
    estimator.update(Duration::ZERO, Duration::from_millis(80));
    assert_eq!(estimator.get(), Duration::from_micros(97_500));
    assert_eq!(estimator.conservative(), Duration::from_micros(97_500));
    for _ in 0..4 {
        assert_eq!(estimator.chrome_loss_rtt(), Duration::from_millis(100));
    }
    estimator.update(Duration::from_millis(20), Duration::from_millis(120));
    assert_eq!(estimator.min(), Duration::from_millis(80));
    assert_eq!(estimator.chrome_loss_rtt(), Duration::from_millis(100));
    assert_eq!(
        estimator.conservative(),
        Duration::from_millis(120),
        "loss-specific adjusted input must not replace the public raw latest RTT"
    );
    if quantized {
        let previous = (
            estimator.sampled_rtt_inputs(),
            estimator.min(),
            estimator.conservative(),
            estimator.chrome_loss_rtt(),
        );
        for invalid in [
            Duration::ZERO,
            Duration::from_nanos(999),
            Duration::from_micros(i64::MAX as u64),
            Duration::MAX,
        ] {
            estimator.update(Duration::ZERO, invalid);
            assert_eq!(
                (
                    estimator.sampled_rtt_inputs(),
                    estimator.min(),
                    estimator.conservative(),
                    estimator.chrome_loss_rtt(),
                ),
                previous,
                "a rejected sample must not advance loss history"
            );
        }
    }
}

#[test]
fn pto_alarm_loss_estimator_unquantized_history_preserves_first_and_adjusted_samples() {
    check_loss_estimator_history(false);
}

fn check_loss_precision(factor: f32, expected_us: u64) {
    let mut case = AlarmCase::configured(true, Duration::from_micros(500), Some(factor));
    let trained = case.snapshot();
    assert_eq!(trained.smoothed, Duration::from_micros(1000));
    let started = case.pair.time;
    let low = case.commit_ping();
    let high = case.commit_ping();
    assert_eq!(high, low + 1);
    let losses = case
        .pair
        .client_conn_mut(case.client)
        .stats()
        .path
        .lost_packets;
    let range = high..=high;
    let ack = case.peer_ack(std::slice::from_ref(&range));
    case.pair.time = started + Duration::from_micros(1251);
    case.accept_ack(ack, std::slice::from_ref(&range));
    assert!(case.snapshot().smoothed < Duration::from_micros(1251));
    assert_eq!(case.snapshot().backoff, 0);
    assert!(
        case.pair
            .client_conn_mut(case.client)
            .sent_state_for_pto_test(low)
            .1
    );
    assert!(
        !case
            .pair
            .client_conn_mut(case.client)
            .sent_state_for_pto_test(high)
            .1
    );
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .stats()
            .path
            .lost_packets,
        losses
    );
    let (candidate, space) = case
        .pair
        .client_conn_mut(case.client)
        .loss_candidate_for_alarm_test()
        .unwrap();
    assert_eq!(space, SpaceId::Data);
    assert_eq!(case.snapshot().deadline, Some(candidate));
    eprintln!(
        "LOSS precision factor={factor} raw_rtt_us=1251 low_pn={low} high_pn={high} candidate_ns={} expected_us={expected_us}",
        (candidate - started).as_nanos()
    );
    assert_eq!(candidate - started, Duration::from_micros(expected_us));
    let before = candidate - Duration::from_nanos(1);
    case.pair.time = before;
    case.pair
        .client_conn_mut(case.client)
        .handle_timeout(before);
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .stats()
            .path
            .lost_packets,
        losses
    );
    assert_eq!(case.snapshot().backoff, 0);
    assert_eq!(case.snapshot().deadline, Some(candidate));
    LossTransition {
        case,
        low,
        armed: candidate,
        candidate,
        lost_before: losses,
    }
    .assert_real_loss();
}

#[test]
fn pto_alarm_loss_precision_chrome_initial_factor_truncates_shifted_microseconds() {
    check_loss_precision(1.25, 1563);
}

#[test]
fn pto_alarm_loss_precision_chrome_native_factor_truncates_shifted_microseconds() {
    check_loss_precision(9.0 / 8.0, 1407);
}

fn loss_precision_candidate(chrome: bool, factor: f32, raw_us: u64) -> Duration {
    let mut case = AlarmCase::configured(chrome, Duration::from_micros(500), Some(factor));
    let start = case.pair.time;
    let low = case.commit_ping();
    let high = case.commit_ping();
    assert_eq!(high, low + 1);
    let losses = case
        .pair
        .client_conn_mut(case.client)
        .stats()
        .path
        .lost_packets;
    let range = high..=high;
    let ack = case.peer_ack(std::slice::from_ref(&range));
    case.pair.time = start + Duration::from_micros(raw_us);
    case.accept_ack(ack, std::slice::from_ref(&range));
    assert!(case.snapshot().smoothed < Duration::from_micros(raw_us));
    assert_eq!(case.snapshot().backoff, 0);
    assert!(
        case.pair
            .client_conn_mut(case.client)
            .sent_state_for_pto_test(low)
            .1
    );
    assert!(
        !case
            .pair
            .client_conn_mut(case.client)
            .sent_state_for_pto_test(high)
            .1
    );
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .stats()
            .path
            .lost_packets,
        losses
    );
    let (candidate, space) = case
        .pair
        .client_conn_mut(case.client)
        .loss_candidate_for_alarm_test()
        .unwrap();
    assert_eq!(space, SpaceId::Data);
    assert_eq!(case.snapshot().deadline, Some(candidate));
    eprintln!(
        "LOSS precision control chrome={chrome} factor={factor:?} raw_us={raw_us} delay_ns={}",
        (candidate - start).as_nanos()
    );
    candidate - start
}

#[test]
fn pto_alarm_loss_precision_disabled_retains_fractional_microseconds() {
    assert_eq!(
        loss_precision_candidate(false, 1.25, 1251),
        Duration::from_nanos(1_563_750)
    );
    assert_eq!(
        loss_precision_candidate(false, 1.125, 1251),
        Duration::from_nanos(1_407_375)
    );
}

#[test]
fn pto_alarm_loss_precision_custom_and_adjacent_factors_keep_duration_multiplication() {
    for factor in [
        1.5,
        f32::from_bits(1.25_f32.to_bits() + 1),
        f32::from_bits(1.125_f32.to_bits() - 1),
    ] {
        assert_eq!(
            loss_precision_candidate(true, factor, 1251),
            loss_precision_candidate(false, factor, 1251)
        );
    }
    assert_eq!(
        loss_precision_candidate(true, 1.5, 1251),
        Duration::from_nanos(1_876_500)
    );
}

#[test]
fn pto_alarm_loss_precision_large_integer_microseconds_remain_exact() {
    assert_eq!(
        loss_precision_candidate(true, 1.25, 16_777_217),
        Duration::from_micros(20_971_521)
    );
    assert_eq!(
        loss_precision_candidate(true, 1.125, 16_777_217),
        Duration::from_micros(18_874_369)
    );
}

#[test]
fn pto_alarm_loss_estimator_quantized_history_preserves_first_and_adjusted_samples() {
    check_loss_estimator_history(true);
}
