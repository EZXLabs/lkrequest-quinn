use super::*;
use crate::packet::SpaceId;

struct Case {
    pair: Pair,
    client: ConnectionHandle,
    server: ConnectionHandle,
}

fn configured(enabled: Option<bool>) -> (Pair, ClientConfig) {
    let mut server = server_config();
    let mut server_transport = TransportConfig::default();
    server_transport
        .mtu_discovery_config(None)
        .enable_ecn(false)
        .discard_blocked_close(true);
    server.transport_config(Arc::new(server_transport));
    let mut client = client_config_with_deterministic_pns();
    let transport = Arc::get_mut(&mut client.transport).unwrap();
    transport.mtu_discovery_config(None).enable_ecn(false);
    if let Some(enabled) = enabled {
        transport.discard_blocked_close(enabled);
    }
    (Pair::new(Default::default(), server), client)
}

impl Case {
    fn new(enabled: Option<bool>) -> Self {
        let (mut pair, config) = configured(enabled);
        let (client, server) = pair.connect_with(config);
        let snapshot = pair.client_conn_mut(client).pto_timing_for_test();
        assert!(!snapshot.handshaking && snapshot.confirmed && snapshot.has_data_keys);
        Self {
            pair,
            client,
            server,
        }
    }

    fn close_client(&mut self) {
        let now = self.pair.time;
        self.pair.client_conn_mut(self.client).close(
            now,
            VarInt::from_u32(259),
            Bytes::from_static(b"duplicate control"),
        );
    }

    fn assert_client_silent(&mut self) {
        let now = self.pair.time;
        assert!(
            self.pair
                .client_conn_mut(self.client)
                .poll_transmit(now, 1, &mut Vec::new())
                .is_none()
        );
    }

    fn deliver_server(&mut self, packets: Vec<(Option<EcnCodepoint>, BytesMut)>) -> Vec<Frame> {
        let remote = self.pair.server.addr;
        let now = self.pair.time;
        packets
            .into_iter()
            .flat_map(|packet| receive(&mut self.pair.client, remote, self.client, now, packet))
            .collect()
    }
}

fn output(connection: &mut Connection, now: Instant) -> Vec<(Option<EcnCodepoint>, BytesMut)> {
    let mut result = Vec::new();
    for _ in 0..16 {
        let mut bytes = Vec::new();
        let Some(transmit) = connection.poll_transmit(now, 1, &mut bytes) else {
            return result;
        };
        assert!(transmit.segment_size.is_none());
        result.push((transmit.ecn, BytesMut::from(&bytes[..transmit.size])));
    }
    panic!("bounded close fixture produced too many datagrams");
}

fn receive(
    endpoint: &mut TestEndpoint,
    remote: SocketAddr,
    handle: ConnectionHandle,
    now: Instant,
    packet: (Option<EcnCodepoint>, BytesMut),
) -> Vec<Frame> {
    let Some(DatagramEvent::ConnectionEvent(actual, event)) =
        endpoint.handle(now, remote, None, packet.0, packet.1, &mut Vec::new())
    else {
        panic!("encrypted packet must route to its real peer");
    };
    assert_eq!(actual, handle);
    let connection = endpoint.connections.get_mut(&handle).unwrap();
    let (_, payload) = connection.decode_packet_with_number(&event).unwrap();
    let frames = frame::Iter::new(payload.into())
        .unwrap()
        .map(Result::unwrap)
        .collect();
    connection.handle_event(event);
    frames
}

fn assert_application_close(frames: &[Frame], code: u64) {
    assert!(frames.iter().any(|frame| matches!(frame,
        Frame::Close(frame::Close::Application(close)) if close.error_code.into_inner() == code)));
}

#[test]
fn blocked_close_confirmed_client_suppresses_without_early_drain() {
    let mut case = Case::new(Some(true));
    assert!(
        !case
            .pair
            .client_conn_mut(case.client)
            .discard_blocked_close()
    );
    case.close_client();
    let deadline = case
        .pair
        .client_conn_mut(case.client)
        .poll_timeout()
        .unwrap();
    assert!(
        case.pair
            .client_conn_mut(case.client)
            .discard_blocked_close()
    );
    assert!(case.pair.client_conn_mut(case.client).is_closed());
    assert!(!case.pair.client_conn_mut(case.client).is_draining());
    assert!(!case.pair.client_conn_mut(case.client).is_drained());
    assert_eq!(
        case.pair.client_conn_mut(case.client).poll_timeout(),
        Some(deadline)
    );
    case.assert_client_silent();
}

#[test]
fn blocked_close_default_and_explicit_off_keep_application_close() {
    for enabled in [None, Some(false)] {
        let mut case = Case::new(enabled);
        case.close_client();
        assert!(
            !case
                .pair
                .client_conn_mut(case.client)
                .discard_blocked_close()
        );
        let now = case.pair.time;
        let packets = output(case.pair.client_conn_mut(case.client), now);
        assert_eq!(packets.len(), 1);
        let remote = case.pair.client.addr;
        let frames = receive(
            &mut case.pair.server,
            remote,
            case.server,
            now,
            packets.into_iter().next().unwrap(),
        );
        assert_application_close(&frames, 259);
    }
}

#[test]
fn blocked_close_enabled_writable_close_still_reaches_peer() {
    let mut case = Case::new(Some(true));
    case.close_client();
    let now = case.pair.time;
    let packets = output(case.pair.client_conn_mut(case.client), now);
    assert_eq!(packets.len(), 1);
    let remote = case.pair.client.addr;
    let frames = receive(
        &mut case.pair.server,
        remote,
        case.server,
        now,
        packets.into_iter().next().unwrap(),
    );
    assert_application_close(&frames, 259);
    assert!(std::iter::from_fn(|| case.pair.server_conn_mut(case.server).poll()).any(|event|
        matches!(event, Event::ConnectionLost { reason: ConnectionError::ApplicationClosed(close) }
            if close.error_code.into_inner() == 259)));
}

#[test]
fn blocked_close_serialized_close_does_not_rearm_on_authenticated_ping() {
    let mut case = Case::new(Some(true));
    case.close_client();
    let now = case.pair.time;
    let unsent = output(case.pair.client_conn_mut(case.client), now);
    assert_eq!(unsent.len(), 1, "runtime owns this unsent close ciphertext");
    assert!(
        case.pair
            .client_conn_mut(case.client)
            .discard_blocked_close()
    );
    let next_number = case
        .pair
        .client_conn_mut(case.client)
        .pto_state_for_test(SpaceId::Data)
        .0;
    case.pair.server_conn_mut(case.server).ping();
    let ping = output(case.pair.server_conn_mut(case.server), now);
    assert!(!ping.is_empty());
    assert!(
        case.deliver_server(ping)
            .iter()
            .any(|frame| matches!(frame, Frame::Ping))
    );
    case.assert_client_silent();
    assert_eq!(
        case.pair
            .client_conn_mut(case.client)
            .pto_state_for_test(SpaceId::Data)
            .0,
        next_number
    );
}

#[test]
fn blocked_close_repeated_local_close_preserves_suppression_and_deadline() {
    let mut case = Case::new(Some(true));
    case.close_client();
    let deadline = case
        .pair
        .client_conn_mut(case.client)
        .poll_timeout()
        .unwrap();
    assert!(
        case.pair
            .client_conn_mut(case.client)
            .discard_blocked_close()
    );
    case.pair.time += Duration::from_millis(1);
    let now = case.pair.time;
    case.pair
        .client_conn_mut(case.client)
        .close(now, VarInt::from_u32(999), Bytes::new());
    assert_eq!(
        case.pair.client_conn_mut(case.client).poll_timeout(),
        Some(deadline)
    );
    case.assert_client_silent();
}

#[test]
fn blocked_close_handshaking_client_keeps_legacy_close() {
    let (mut pair, config) = configured(Some(true));
    let client = pair.begin_connect(config);
    assert!(pair.client_conn_mut(client).is_handshaking());
    assert!(
        !pair
            .client_conn_mut(client)
            .pto_timing_for_test()
            .has_data_keys
    );
    let now = pair.time;
    pair.client_conn_mut(client)
        .close(now, VarInt::from_u32(259), Bytes::new());
    assert!(!pair.client_conn_mut(client).discard_blocked_close());
    assert!(!output(pair.client_conn_mut(client), now).is_empty());
}

#[test]
fn blocked_close_established_but_unconfirmed_client_keeps_legacy_close() {
    let (mut pair, config) = configured(Some(true));
    let client = pair.begin_connect(config);
    pair.drive_client();
    pair.drive_server();
    pair.drive_client();
    let snapshot = pair.client_conn_mut(client).pto_timing_for_test();
    assert!(!snapshot.handshaking && snapshot.has_data_keys && !snapshot.confirmed);
    let now = pair.time;
    pair.client_conn_mut(client)
        .close(now, VarInt::from_u32(259), Bytes::new());
    assert!(!pair.client_conn_mut(client).discard_blocked_close());
    assert!(!output(pair.client_conn_mut(client), now).is_empty());
}

#[test]
fn blocked_close_pending_zero_rtt_keeps_legacy_close() {
    let (mut pair, config) = configured(Some(true));
    let (warm, _) = pair.connect_with(config.clone());
    let now = pair.time;
    pair.client_conn_mut(warm)
        .close(now, VarInt::from_u32(0), Bytes::new());
    pair.drive();
    pair.client
        .addr
        .set_port(CLIENT_PORTS.lock().unwrap().next().unwrap());
    let client = pair.begin_connect(config);
    assert!(pair.client_conn_mut(client).has_0rtt());
    let stream = pair.client_streams(client).open(Dir::Bi).unwrap();
    pair.client_send(client, stream)
        .write(b"early application")
        .unwrap();
    pair.drive_client();
    assert!(pair.client_conn_mut(client).is_handshaking());
    let now = pair.time;
    pair.client_conn_mut(client)
        .close(now, VarInt::from_u32(259), Bytes::new());
    assert!(!pair.client_conn_mut(client).discard_blocked_close());
    assert!(!output(pair.client_conn_mut(client), now).is_empty());
}

#[test]
fn blocked_close_server_keeps_legacy_application_close() {
    let mut case = Case::new(Some(true));
    let now = case.pair.time;
    case.pair
        .server_conn_mut(case.server)
        .close(now, VarInt::from_u32(259), Bytes::new());
    assert!(
        !case
            .pair
            .server_conn_mut(case.server)
            .discard_blocked_close()
    );
    let packets = output(case.pair.server_conn_mut(case.server), now);
    assert_eq!(packets.len(), 1);
    assert_application_close(&case.deliver_server(packets), 259);
}

#[test]
fn blocked_close_transport_error_cannot_be_promoted_by_application_close() {
    let mut case = Case::new(Some(true));
    let now = case.pair.time;
    let unsent = 9_000_000..=9_000_000;
    case.pair
        .server_conn_mut(case.server)
        .queue_ack_for_pto_test(now, std::slice::from_ref(&unsent));
    let packets = output(case.pair.server_conn_mut(case.server), now);
    assert!(!packets.is_empty());
    case.deliver_server(packets);
    assert!(std::iter::from_fn(|| case.pair.client_conn_mut(case.client).poll()).any(|event|
        matches!(event, Event::ConnectionLost { reason: ConnectionError::TransportError(error) }
            if error.code == TransportErrorCode::PROTOCOL_VIOLATION)));
    case.close_client();
    assert!(
        !case
            .pair
            .client_conn_mut(case.client)
            .discard_blocked_close()
    );
    let packets = output(case.pair.client_conn_mut(case.client), now);
    assert_eq!(packets.len(), 1);
    let remote = case.pair.client.addr;
    let frames = receive(
        &mut case.pair.server,
        remote,
        case.server,
        now,
        packets.into_iter().next().unwrap(),
    );
    assert!(frames.iter().any(|frame| matches!(frame,
        Frame::Close(frame::Close::Connection(close)) if close.error_code == TransportErrorCode::PROTOCOL_VIOLATION)));
}

#[test]
fn blocked_close_suppression_survives_peer_close_then_drains_once() {
    let mut case = Case::new(Some(true));
    case.close_client();
    assert!(
        case.pair
            .client_conn_mut(case.client)
            .discard_blocked_close()
    );
    let deadline = case
        .pair
        .client_conn_mut(case.client)
        .poll_timeout()
        .unwrap();
    let now = case.pair.time;
    case.pair
        .server_conn_mut(case.server)
        .close(now, VarInt::from_u32(42), Bytes::new());
    let packets = output(case.pair.server_conn_mut(case.server), now);
    assert_application_close(&case.deliver_server(packets), 42);
    assert!(case.pair.client_conn_mut(case.client).is_draining());
    assert!(
        !case
            .pair
            .client_conn_mut(case.client)
            .discard_blocked_close()
    );
    case.assert_client_silent();
    assert_eq!(
        case.pair.client_conn_mut(case.client).poll_timeout(),
        Some(deadline)
    );
    case.pair
        .client_conn_mut(case.client)
        .handle_timeout(deadline - Duration::from_nanos(1));
    assert!(!case.pair.client_conn_mut(case.client).is_drained());
    assert_eq!(case.pair.client.open_connections(), 1);
    case.pair
        .client_conn_mut(case.client)
        .handle_timeout(deadline);
    assert!(case.pair.client_conn_mut(case.client).is_drained());
    let events: Vec<_> = std::iter::from_fn(|| {
        case.pair
            .client_conn_mut(case.client)
            .poll_endpoint_events()
    })
    .collect();
    assert_eq!(events.iter().filter(|event| event.is_drained()).count(), 1);
    for event in events {
        assert!(case.pair.client.handle_event(case.client, event).is_none());
    }
    assert_eq!(case.pair.client.open_connections(), 0);
    case.pair
        .client_conn_mut(case.client)
        .handle_timeout(deadline + Duration::from_secs(1));
    assert!(
        case.pair
            .client_conn_mut(case.client)
            .poll_endpoint_events()
            .is_none()
    );
}
