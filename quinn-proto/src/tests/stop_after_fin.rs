use super::*;

#[derive(Clone, Copy, Debug)]
enum PeerSignal {
    AckWithheld,
    AckBeforeStop,
    StopBeforeAck,
    FullyAckedEarlier,
}

#[derive(Debug, PartialEq, Eq)]
enum RuntimeDropAction {
    ResetQueued(u64),
    ResetAlreadyQueued(u64),
    Closed,
    Finished,
}

fn emulate_runtime_send_drop(
    pair: &mut Pair,
    client: ConnectionHandle,
    stream: StreamId,
) -> RuntimeDropAction {
    // Mirror quinn::SendStream::drop, without pretending a proto stream handle
    // has that destructor or that a handle dropped earlier runs it again.
    match pair.client_send(client, stream).finish() {
        Ok(()) => RuntimeDropAction::Finished,
        Err(FinishError::Stopped(code)) => {
            if pair.client_send(client, stream).reset(code).is_ok() {
                RuntimeDropAction::ResetQueued(code.into_inner())
            } else {
                RuntimeDropAction::ResetAlreadyQueued(code.into_inner())
            }
        }
        Err(FinishError::ClosedStream) => RuntimeDropAction::Closed,
    }
}

fn transmit(connection: &mut Connection, now: Instant) -> Vec<(Option<EcnCodepoint>, BytesMut)> {
    let mut packets = Vec::new();
    let mut buffer = Vec::new();
    while let Some(sent) = connection.poll_transmit(now, 1, &mut buffer) {
        assert!(sent.segment_size.is_none());
        packets.push((sent.ecn, BytesMut::from(&buffer[..sent.size])));
        buffer.clear();
    }
    packets
}

fn receive(
    endpoint: &mut TestEndpoint,
    remote: SocketAddr,
    connection: ConnectionHandle,
    deliver: bool,
) -> Vec<Frame> {
    let mut frames = Vec::new();
    while let Some((time, ecn, packet)) = endpoint.inbound.pop_front() {
        let Some(DatagramEvent::ConnectionEvent(handle, event)) =
            endpoint.handle(time, remote, None, ecn, packet, &mut Vec::new())
        else {
            panic!("expected an established peer packet");
        };
        assert_eq!(handle, connection);
        let connection = endpoint.connections.get_mut(&handle).unwrap();
        let payload = connection.decode_packet(&event).unwrap();
        frames.extend(
            frame::Iter::new(payload.into())
                .unwrap()
                .map(Result::unwrap)
                .filter(|frame| !matches!(frame, Frame::Padding)),
        );
        if deliver {
            connection.handle_event(event);
        }
    }
    frames
}

fn types(frames: &[Frame]) -> Vec<&'static str> {
    frames
        .iter()
        .map(|frame| match frame {
            Frame::Ack(_) => "ACK",
            Frame::StopSending(_) => "STOP",
            Frame::ResetStream(_) => "RESET",
            Frame::Stream(_) => "STREAM",
            Frame::AckFrequency(_) => "ACK_FREQUENCY",
            Frame::Ping => "PING",
            Frame::ImmediateAck => "IMMEDIATE_ACK",
            other => panic!("unexpected frame in stop fixture: {other:?}"),
        })
        .collect()
}

fn reset_frames(frames: &[Frame], stream: StreamId) -> Vec<(u64, u64)> {
    frames
        .iter()
        .filter_map(|frame| match frame {
            Frame::ResetStream(reset) if reset.id == stream => Some((
                reset.error_code.into_inner(),
                reset.final_offset.into_inner(),
            )),
            _ => None,
        })
        .collect()
}

fn client_output(
    pair: &mut Pair,
    client: ConnectionHandle,
    server: ConnectionHandle,
    deliver: bool,
) -> Vec<Frame> {
    let now = pair.time;
    for (ecn, bytes) in transmit(pair.client_conn_mut(client), now) {
        pair.server.inbound.push_back((now, ecn, bytes));
    }
    let remote = pair.client.addr;
    receive(&mut pair.server, remote, server, deliver)
}

fn server_output(
    pair: &mut Pair,
    client: ConnectionHandle,
    server: ConnectionHandle,
    deliver: bool,
) -> Vec<Frame> {
    let now = pair.time;
    for (ecn, bytes) in transmit(pair.server_conn_mut(server), now) {
        pair.client.inbound.push_back((now, ecn, bytes));
    }
    let remote = pair.server.addr;
    receive(&mut pair.client, remote, client, deliver)
}

#[derive(Debug)]
struct Observation {
    stopped_events: Vec<u64>,
    drop_action: RuntimeDropAction,
    resets: Vec<(u64, u64)>,
    automatic_resets: Vec<(u64, u64)>,
}

fn connected(
    enabled: bool,
    partial_prefix: bool,
    send_window: Option<u64>,
) -> (Pair, ConnectionHandle, ConnectionHandle) {
    let mut server_config = server_config();
    let mut transport = TransportConfig::default();
    transport
        .deterministic_packet_numbers(true)
        .mtu_discovery_config(None)
        .enable_ecn(false)
        .ack_obligation_only(true);
    server_config.transport_config(Arc::new(transport));
    let mut client_config = client_config_with_deterministic_pns();
    let transport = Arc::get_mut(&mut client_config.transport).unwrap();
    transport
        .mtu_discovery_config(None)
        .enable_ecn(false)
        .ack_obligation_only(true)
        .reset_finished_on_stop(enabled);
    if let Some(limit) = send_window {
        transport.send_window(limit);
    }
    if partial_prefix {
        // A genuine negotiated ACK_FREQUENCY lets a missing earlier packet
        // remain delayed, so both legal ACK/STOP wire orders are controllable.
        let mut frequency = AckFrequencyConfig::default();
        frequency.reordering_threshold(0u32.into());
        transport.ack_frequency_config(Some(frequency));
    }
    let mut pair = Pair::new(Default::default(), server_config);
    let (client, server) = pair.connect_with(client_config);
    (pair, client, server)
}

fn run_case(
    signal: PeerSignal,
    code: u64,
    partial_prefix: bool,
    drop_before_stop: bool,
    enabled: bool,
) -> Observation {
    let (mut pair, client, server) = connected(enabled, partial_prefix, None);
    let stream = pair.client_streams(client).open(Dir::Bi).unwrap();
    let now = pair.time;
    if partial_prefix {
        pair.client_send(client, stream).write(b"123").unwrap();
        let prefix = transmit(pair.client_conn_mut(client), now);
        assert_eq!(prefix.len(), 1);
        // Deliberately do not deliver the prefix packet. Its bytes remain real
        // sent but unacknowledged state, without direct send-state mutation.
        pair.client_send(client, stream).write(b"4567").unwrap();
    } else {
        pair.client_send(client, stream).write(b"1234567").unwrap();
    }
    pair.client_send(client, stream).finish().unwrap();
    let early_drop = drop_before_stop.then(|| emulate_runtime_send_drop(&mut pair, client, stream));
    if let Some(action) = &early_drop {
        assert_eq!(*action, RuntimeDropAction::Closed);
    }
    let outgoing = transmit(pair.client_conn_mut(client), now);
    assert_eq!(outgoing.len(), 1);
    for (ecn, bytes) in outgoing {
        pair.server.inbound.push_back((now, ecn, bytes));
    }
    let remote = pair.client.addr;
    let incoming = receive(&mut pair.server, remote, server, true);
    assert!(
        incoming
            .iter()
            .any(|frame| matches!(frame, Frame::Stream(data)
        if data.id == stream && data.fin && data.offset + data.data.len() as u64 == 7))
    );
    assert_eq!(pair.server_streams(server).accept(Dir::Bi), Some(stream));
    assert!(
        pair.client_send(client, stream)
            .stopped()
            .unwrap()
            .is_none()
    );

    if !matches!(signal, PeerSignal::StopBeforeAck) {
        pair.time += Duration::from_millis(25);
        let now = pair.time;
        pair.server_conn_mut(server).handle_timeout(now);
        if matches!(
            signal,
            PeerSignal::AckWithheld | PeerSignal::FullyAckedEarlier
        ) {
            let outgoing = transmit(pair.server_conn_mut(server), now);
            assert_eq!(outgoing.len(), 1);
            for (ecn, bytes) in outgoing {
                pair.client.inbound.push_back((now, ecn, bytes));
            }
            let remote = pair.server.addr;
            let acks = receive(
                &mut pair.client,
                remote,
                client,
                matches!(signal, PeerSignal::FullyAckedEarlier),
            );
            assert_eq!(types(&acks), vec!["ACK"]);
            if matches!(signal, PeerSignal::FullyAckedEarlier) {
                assert!(pair.client_send(client, stream).stopped().is_err());
            }
        }
    }
    pair.server_recv(server, stream)
        .stop(VarInt::from_u64(code).unwrap())
        .unwrap();
    let now = pair.time;
    let outgoing = transmit(pair.server_conn_mut(server), now);
    assert_eq!(outgoing.len(), 1);
    for (ecn, bytes) in outgoing {
        pair.client.inbound.push_back((now, ecn, bytes));
    }
    let remote = pair.server.addr;
    let frames = receive(&mut pair.client, remote, client, true);
    let expected = match signal {
        PeerSignal::AckWithheld | PeerSignal::FullyAckedEarlier => vec!["STOP"],
        PeerSignal::AckBeforeStop => vec!["ACK", "STOP"],
        PeerSignal::StopBeforeAck => vec!["STOP", "ACK"],
    };
    assert_eq!(types(&frames), expected);
    assert!(
        frames
            .iter()
            .any(|frame| matches!(frame, Frame::StopSending(stop)
        if stop.id == stream && stop.error_code.into_inner() == code))
    );
    if partial_prefix {
        let ack = frames
            .iter()
            .find_map(|frame| match frame {
                Frame::Ack(ack) => Some(ack),
                _ => None,
            })
            .unwrap();
        assert!(
            !ack.iter().any(|range| range.contains(&(ack.largest - 1))),
            "ACK of FIN must leave its earlier data packet unacknowledged"
        );
    }
    let mut stopped_events = Vec::new();
    while let Some(event) = pair.client_conn_mut(client).poll() {
        if let Event::Stream(StreamEvent::Stopped { id, error_code }) = event {
            assert_eq!(id, stream);
            stopped_events.push(error_code.into_inner());
        }
    }

    // Observe proto output before any application reaction, independently of
    // the runtime SendStream destructor emulated below.
    let outgoing = transmit(pair.client_conn_mut(client), now);
    for (ecn, bytes) in outgoing {
        pair.server.inbound.push_back((now, ecn, bytes));
    }
    let remote = pair.client.addr;
    let bare_proto_frames = receive(&mut pair.server, remote, server, true);
    let automatic_resets = reset_frames(&bare_proto_frames, stream);
    if !enabled {
        assert!(automatic_resets.is_empty());
    }
    let drop_action =
        early_drop.unwrap_or_else(|| emulate_runtime_send_drop(&mut pair, client, stream));
    let outgoing = transmit(pair.client_conn_mut(client), now);
    for (ecn, bytes) in outgoing {
        pair.server.inbound.push_back((now, ecn, bytes));
    }
    let remote = pair.client.addr;
    let mut resets = automatic_resets.clone();
    resets.extend(reset_frames(
        &receive(&mut pair.server, remote, server, true),
        stream,
    ));

    // STOP affects only the upload direction. Check the response remains usable.
    pair.server_send(server, stream)
        .write(b"response survives")
        .unwrap();
    pair.server_send(server, stream).finish().unwrap();
    pair.drive();
    assert_eq!(
        stream_chunks(pair.client_recv(client, stream)),
        b"response survives"
    );
    let observation = Observation {
        stopped_events,
        drop_action,
        resets,
        automatic_resets,
    };
    eprintln!(
        "FIN/STOP signal={signal:?}, code={code}, missing_prefix={partial_prefix}, dropped_before_stop={drop_before_stop}, policy={enabled}: {observation:?}"
    );
    observation
}

#[test]
fn stop_after_fin_native_retained_handle_and_prior_ack_controls() {
    for code in [0, 256, 268] {
        let pending = run_case(PeerSignal::AckWithheld, code, false, false, false);
        assert_eq!(pending.stopped_events, vec![code]);
        assert_eq!(pending.drop_action, RuntimeDropAction::ResetQueued(code));
        assert_eq!(pending.resets, vec![(code, 7)]);
        let same_packet = run_case(PeerSignal::AckBeforeStop, code, false, false, false);
        assert!(same_packet.stopped_events.is_empty());
        assert_eq!(same_packet.drop_action, RuntimeDropAction::Closed);
        assert!(same_packet.resets.is_empty());
        for dropped in [false, true] {
            let prior_ack = run_case(PeerSignal::FullyAckedEarlier, code, false, dropped, false);
            assert!(prior_ack.stopped_events.is_empty());
            assert!(prior_ack.resets.is_empty());
        }
    }
}

#[test]
fn stop_after_fin_partial_prefix_ack_leaves_reset_possible_in_both_orders() {
    for code in [0, 256, 268] {
        for order in [PeerSignal::AckBeforeStop, PeerSignal::StopBeforeAck] {
            for enabled in [false, true] {
                let observed = run_case(order, code, true, false, enabled);
                assert_eq!(observed.stopped_events, vec![code]);
                assert_eq!(
                    observed.drop_action,
                    if enabled {
                        RuntimeDropAction::ResetAlreadyQueued(code)
                    } else {
                        RuntimeDropAction::ResetQueued(code)
                    }
                );
                assert_eq!(observed.resets, vec![(code, 7)]);
                assert_eq!(observed.automatic_resets.len(), usize::from(enabled));
            }
        }
    }
}

#[test]
fn stop_after_fin_chrome_expected_reset_when_handle_was_dropped_before_stop() {
    let mut missing = Vec::new();
    for code in [0, 256, 268] {
        let observed = run_case(PeerSignal::AckWithheld, code, false, true, true);
        assert_eq!(observed.stopped_events, vec![code]);
        assert_eq!(observed.automatic_resets, vec![(code, 7)]);
        if observed.resets != [(code, 7)] {
            missing.push(observed);
        }
    }
    assert!(
        missing.is_empty(),
        "Chrome resets an unacknowledged finished upload synchronously: {missing:?}"
    );
}

#[test]
fn stop_after_fin_chrome_expected_reset_when_stop_precedes_full_ack_in_one_packet() {
    let mut missing = Vec::new();
    for code in [0, 256, 268] {
        let observed = run_case(PeerSignal::StopBeforeAck, code, false, false, true);
        assert_eq!(observed.stopped_events, vec![code]);
        assert_eq!(observed.automatic_resets, vec![(code, 7)]);
        if observed.resets != [(code, 7)] {
            missing.push(observed);
        }
    }
    assert!(
        missing.is_empty(),
        "Chrome queues RESET during STOP handling before the following ACK: {missing:?}"
    );
}

#[test]
fn stop_after_fin_default_off_preserves_old_no_reset_cases() {
    assert!(!TransportConfig::default().reset_finished_on_stop);
    for code in [0, 256, 268] {
        for (signal, dropped) in [
            (PeerSignal::AckWithheld, true),
            (PeerSignal::StopBeforeAck, false),
        ] {
            let observed = run_case(signal, code, false, dropped, false);
            assert_eq!(observed.stopped_events, vec![code]);
            assert!(observed.automatic_resets.is_empty());
            assert!(observed.resets.is_empty());
        }
        for signal in [PeerSignal::AckBeforeStop, PeerSignal::FullyAckedEarlier] {
            let observed = run_case(signal, code, false, true, true);
            assert!(observed.stopped_events.is_empty());
            assert!(observed.resets.is_empty());
        }
    }
}

#[test]
fn stop_after_fin_buffered_fin_duplicate_codes_and_late_ack_preserve_credit() {
    for first_code in [0u64, 256, 268] {
        let (mut pair, client, server) = connected(true, false, Some(7));
        let stream = pair.client_streams(client).open(Dir::Bi).unwrap();
        pair.client_send(client, stream).write(b"1").unwrap();
        let initial = client_output(&mut pair, client, server, true);
        assert!(initial.iter().any(|frame| matches!(frame, Frame::Stream(data) if data.id == stream && !data.fin && data.data == b"1"[..])));
        assert_eq!(pair.server_streams(server).accept(Dir::Bi), Some(stream));
        pair.client_send(client, stream).write(b"234567").unwrap();
        pair.client_send(client, stream).finish().unwrap();
        // FIN and the final six bytes remain queued; no client transmit here.
        pair.server_conn_mut(server)
            .queue_stop_for_test(stream, VarInt::from_u64(first_code).unwrap());
        let stop_and_ack = server_output(&mut pair, client, server, true);
        assert_eq!(types(&stop_and_ack), vec!["STOP", "ACK"]);
        assert_eq!(
            pair.client_send(client, stream).stopped().unwrap(),
            Some(VarInt::from_u64(first_code).unwrap())
        );
        pair.server_conn_mut(server)
            .queue_stop_for_test(stream, VarInt::from_u64(first_code).unwrap());
        pair.server_conn_mut(server)
            .queue_stop_for_test(stream, VarInt::from_u64(first_code + 1).unwrap());
        let duplicates = server_output(&mut pair, client, server, true);
        assert_eq!(types(&duplicates), vec!["STOP", "STOP"]);
        assert_eq!(
            pair.client_send(client, stream).stopped().unwrap(),
            Some(VarInt::from_u64(first_code).unwrap())
        );

        let other = pair.client_streams(client).open(Dir::Bi).unwrap();
        assert_eq!(
            pair.client_send(client, other).write(b"abcdefg"),
            Ok(7),
            "reset must release the original seven-byte send window once"
        );
        let frames = client_output(&mut pair, client, server, true);
        assert_eq!(reset_frames(&frames, stream), vec![(first_code, 7)]);
        assert!(
            !frames
                .iter()
                .any(|frame| matches!(frame, Frame::Stream(data) if data.id == stream)),
            "abandoned buffered FIN/data must not be transmitted"
        );
        assert_eq!(
            pair.client_conn_mut(client).stats().frame_tx.reset_stream,
            1
        );
        pair.drive();
        assert!(
            pair.client_send(client, stream).stopped().is_err(),
            "RESET ACK must free the send state"
        );
        pair.server_send(server, stream)
            .write(b"response survives")
            .unwrap();
        pair.server_send(server, stream).finish().unwrap();
        pair.drive();
        assert_eq!(
            stream_chunks(pair.client_recv(client, stream)),
            b"response survives"
        );
    }
}

#[test]
fn stop_after_fin_policy_does_not_change_ready_stream_zero_credit_errors() {
    for enabled in [false, true] {
        for code in [0u64, 256, 268] {
            let (mut pair, client, server) = connected(enabled, false, Some(7));
            let stream = pair.client_streams(client).open(Dir::Bi).unwrap();
            pair.client_send(client, stream).write(b"1234567").unwrap();
            client_output(&mut pair, client, server, true);
            assert_eq!(pair.server_streams(server).accept(Dir::Bi), Some(stream));
            assert_eq!(
                pair.client_send(client, stream).write(b"x"),
                Err(WriteError::Blocked)
            );
            pair.time += Duration::from_millis(25);
            let now = pair.time;
            pair.server_conn_mut(server).handle_timeout(now);
            assert_eq!(
                types(&server_output(&mut pair, client, server, false)),
                vec!["ACK"]
            );
            pair.server_recv(server, stream)
                .stop(VarInt::from_u64(code).unwrap())
                .unwrap();
            assert_eq!(
                types(&server_output(&mut pair, client, server, true)),
                vec!["STOP"]
            );
            assert_eq!(
                pair.client_send(client, stream).write(b"x"),
                Err(WriteError::Stopped(VarInt::from_u64(code).unwrap()))
            );
            assert!(
                reset_frames(&client_output(&mut pair, client, server, true), stream).is_empty()
            );
            assert_eq!(
                pair.client_conn_mut(client).stats().frame_tx.reset_stream,
                0
            );
            assert_eq!(
                emulate_runtime_send_drop(&mut pair, client, stream),
                RuntimeDropAction::ResetQueued(code)
            );
            assert_eq!(
                reset_frames(&client_output(&mut pair, client, server, true), stream),
                vec![(code, 7)]
            );
        }
    }
}

#[test]
fn stop_after_fin_reset_loss_retransmits_original_code_and_ack_frees_state() {
    for code in [0u64, 256, 268] {
        let (mut pair, client, server) = connected(true, false, Some(7));
        let stream = pair.client_streams(client).open(Dir::Bi).unwrap();
        pair.client_send(client, stream).write(b"1234567").unwrap();
        pair.client_send(client, stream).finish().unwrap();
        client_output(&mut pair, client, server, true);
        assert_eq!(pair.server_streams(server).accept(Dir::Bi), Some(stream));
        pair.server_conn_mut(server)
            .queue_stop_for_test(stream, VarInt::from_u64(code).unwrap());
        assert_eq!(
            types(&server_output(&mut pair, client, server, true)),
            vec!["STOP", "ACK"]
        );
        let lost = client_output(&mut pair, client, server, false);
        assert_eq!(reset_frames(&lost, stream), vec![(code, 7)]);
        let timeout = pair.client_conn_mut(client).poll_timeout().unwrap();
        pair.time = timeout;
        pair.client_conn_mut(client).handle_timeout(timeout);
        let retransmitted = client_output(&mut pair, client, server, true);
        let resets = reset_frames(&retransmitted, stream);
        assert!(!resets.is_empty());
        assert!(resets.iter().all(|reset| *reset == (code, 7)));
        assert!(
            !retransmitted
                .iter()
                .any(|frame| matches!(frame, Frame::Stream(data) if data.id == stream))
        );
        assert_eq!(
            pair.client_conn_mut(client).stats().frame_tx.reset_stream,
            1 + resets.len() as u64
        );
        pair.drive();
        assert!(pair.client_send(client, stream).stopped().is_err());
        let other = pair.client_streams(client).open(Dir::Bi).unwrap();
        assert_eq!(pair.client_send(client, other).write(b"abcdefg"), Ok(7));
        pair.server_send(server, stream)
            .write(b"response survives")
            .unwrap();
        pair.server_send(server, stream).finish().unwrap();
        pair.drive();
        assert_eq!(
            stream_chunks(pair.client_recv(client, stream)),
            b"response survives"
        );
    }
}

#[test]
fn stop_after_fin_actual_zero_rtt_stop_does_not_reset_finished_server_stream() {
    let mut server_config = server_config();
    let mut transport = TransportConfig::default();
    transport
        .reset_finished_on_stop(true)
        .mtu_discovery_config(None);
    server_config.transport_config(Arc::new(transport));
    let mut pair = Pair::new(Default::default(), server_config);
    let config = client_config();
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
    let stream = pair.client_streams(client).open(Dir::Bi).unwrap();
    pair.client_send(client, stream)
        .write(b"early request")
        .unwrap();
    pair.drive_client();
    pair.drive_server();
    let server = pair.server.assert_accept();
    assert_eq!(pair.server_streams(server).accept(Dir::Bi), Some(stream));
    pair.server_send(server, stream)
        .write(b"finished response")
        .unwrap();
    pair.server_send(server, stream).finish().unwrap();
    // Keep the server flight away from the client until its STOP is protected
    // with real 0-RTT keys. The server's response FIN is only application-queued.
    pair.client_recv(client, stream)
        .stop(268u32.into())
        .unwrap();
    let now = pair.time;
    let outgoing = transmit(pair.client_conn_mut(client), now);
    assert_eq!(outgoing.len(), 1);
    assert_eq!(
        outgoing[0].1[0] & 0xb0,
        0x90,
        "STOP must use a 0-RTT long header, independent of fixed-bit GREASE"
    );
    assert_eq!(
        u32::from_be_bytes(outgoing[0].1[1..5].try_into().unwrap()),
        1
    );
    for (ecn, bytes) in outgoing {
        pair.server.inbound.push_back((now, ecn, bytes));
    }
    let remote = pair.client.addr;
    let early_stop = receive(&mut pair.server, remote, server, true);
    assert!(early_stop.iter().any(|frame| matches!(frame, Frame::StopSending(stop) if stop.id == stream && stop.error_code.into_inner() == 268)));
    assert_eq!(
        pair.server_send(server, stream).stopped().unwrap(),
        Some(268u32.into())
    );
    let response = transmit(pair.server_conn_mut(server), now);
    assert_eq!(
        pair.server_conn_mut(server).stats().frame_tx.reset_stream,
        0
    );
    pair.drive_client();
    for (ecn, bytes) in response {
        pair.client.inbound.push_back((now, ecn, bytes));
    }
    let remote = pair.server.addr;
    let received = receive(&mut pair.client, remote, client, true);
    assert!(reset_frames(&received, stream).is_empty());
    pair.drive();
    assert!(pair.client_conn_mut(client).accepted_0rtt());
}
