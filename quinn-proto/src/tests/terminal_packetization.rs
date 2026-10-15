use super::*;
use crate::{packet::SpaceId, shared::ConnectionEventInner};

#[derive(Debug)]
struct ObservedPacket {
    space: SpaceId,
    number: u64,
    crypto_bytes: usize,
    close: Option<TransportErrorCode>,
    frame_types: Vec<&'static str>,
}

#[derive(Debug)]
struct Observation {
    limit: u64,
    before: u64,
    after: u64,
    next_before: u64,
    next_after: u64,
    closed: bool,
    drained: bool,
    packets: Vec<ObservedPacket>,
}

fn observe(space: SpaceId, offset: i64) -> Observation {
    let mut pair = Pair::default_with_deterministic_pns();
    let client = pair.begin_connect(client_config_with_deterministic_pns());
    pair.drive_client();
    pair.server.drive_incoming(pair.time, pair.client.addr);
    let server = pair.server.assert_accept();

    if space == SpaceId::Initial {
        let timeout = pair.client_conn_mut(client).poll_timeout().unwrap();
        pair.time = timeout;
        pair.client_conn_mut(client).handle_timeout(timeout);
    } else {
        assert_eq!(space, SpaceId::Handshake);
        pair.drive_server();
        while let Some((at, ecn, bytes)) = pair.client.inbound.pop_front() {
            let Some(DatagramEvent::ConnectionEvent(handle, event)) =
                pair.client
                    .handle(at, pair.server.addr, None, ecn, bytes, &mut Vec::new())
            else {
                panic!("real server handshake flight must route to the client");
            };
            assert_eq!(handle, client);
            pair.client_conn_mut(client).handle_event(event);
        }
        assert!(!pair.client_conn_mut(client).is_handshaking());
    }

    let (limit, _, next_before) = pair
        .client_conn_mut(client)
        .terminal_packetization_state_for_test(space);
    let before = limit.checked_add_signed(offset).unwrap();
    pair.client_conn_mut(client)
        .set_terminal_packetization_count_for_test(space, before);
    assert_eq!(
        pair.client_conn_mut(client)
            .terminal_packetization_state_for_test(space),
        (limit, before, next_before),
        "only the usage counter changes; the real keys and packet numbers remain"
    );

    let now = pair.time;
    let mut buffer = Vec::new();
    let transmit = pair
        .client_conn_mut(client)
        .poll_transmit(now, 1, &mut buffer);
    let (_, after, next_after) = pair
        .client_conn_mut(client)
        .terminal_packetization_state_for_test(space);
    let mut observation = Observation {
        limit,
        before,
        after,
        next_before,
        next_after,
        closed: pair.client_conn_mut(client).is_closed(),
        drained: pair.client_conn_mut(client).is_drained(),
        packets: Vec::new(),
    };
    if let Some(transmit) = transmit {
        assert!(transmit.segment_size.is_none());
        let mut remaining = Some(BytesMut::from(&buffer[..transmit.size]));
        while let Some(bytes) = remaining {
            let Some(DatagramEvent::ConnectionEvent(handle, mut event)) = pair.server.handle(
                now,
                pair.client.addr,
                None,
                transmit.ecn,
                bytes,
                &mut Vec::new(),
            ) else {
                panic!("actual encrypted output must route to the existing peer");
            };
            assert_eq!(handle, server);
            let ConnectionEventInner::Datagram(datagram) = &mut event.0 else {
                unreachable!()
            };
            let packet_space = datagram.first_decode.space().unwrap();
            remaining = datagram.remaining.take();
            let (number, payload) = pair
                .server_conn_mut(server)
                .decode_packet_with_number(&event)
                .expect("output must authenticate with the unchanged real peer keys");
            let mut packet = ObservedPacket {
                space: packet_space,
                number: number.unwrap(),
                crypto_bytes: 0,
                close: None,
                frame_types: Vec::new(),
            };
            for frame in frame::Iter::new(payload.into()).unwrap() {
                match frame.unwrap() {
                    Frame::Padding => (),
                    Frame::Crypto(crypto) => {
                        packet.crypto_bytes += crypto.data.len();
                        packet.frame_types.push("CRYPTO");
                    }
                    Frame::Close(frame::Close::Connection(close)) => {
                        assert!(packet.close.replace(close.error_code).is_none());
                        packet.frame_types.push("CONNECTION_CLOSE");
                    }
                    Frame::Ack(_) => packet.frame_types.push("ACK"),
                    Frame::Ping => packet.frame_types.push("PING"),
                    _ => packet.frame_types.push("OTHER"),
                }
            }
            observation.packets.push(packet);
        }
    }
    eprintln!("terminal boundary {space:?} offset={offset}: {observation:?}");
    observation
}

fn last_use_is_only_close(space: SpaceId) -> bool {
    let result = observe(space, -1);
    assert_eq!(result.before + 1, result.limit);
    assert_eq!(result.after, result.limit);
    assert_eq!(result.next_after, result.next_before + 1);
    assert!(result.closed && !result.drained);
    let packet = result
        .packets
        .iter()
        .find(|packet| packet.space == space)
        .unwrap();
    assert_eq!(packet.number, result.next_before);
    result.packets.iter().all(|packet| packet.crypto_bytes == 0)
        && packet.close == Some(TransportErrorCode::AEAD_LIMIT_REACHED)
}

fn exhausted_keys_emit_nothing(space: SpaceId, offset: i64) -> bool {
    let result = observe(space, offset);
    assert!(result.before >= result.limit);
    result.drained
        && result.after == result.before
        && result.next_after == result.next_before
        && result.packets.is_empty()
}

fn usable_keys_send_crypto(space: SpaceId) -> bool {
    let result = observe(space, -2);
    assert_eq!(result.after, result.before + 1);
    assert_eq!(result.next_after, result.next_before + 1);
    !result.closed
        && result
            .packets
            .iter()
            .any(|packet| packet.space == space && packet.crypto_bytes > 0)
        && result.packets.iter().all(|packet| packet.close.is_none())
}

#[test]
fn terminal_packetization_initial_last_use_is_only_close() {
    assert!(last_use_is_only_close(SpaceId::Initial));
}

#[test]
fn terminal_packetization_handshake_last_use_is_only_close() {
    assert!(last_use_is_only_close(SpaceId::Handshake));
}

#[test]
fn terminal_packetization_initial_at_limit_does_not_encrypt() {
    assert!(exhausted_keys_emit_nothing(SpaceId::Initial, 0));
}

#[test]
fn terminal_packetization_handshake_at_limit_does_not_encrypt() {
    assert!(exhausted_keys_emit_nothing(SpaceId::Handshake, 0));
}

#[test]
fn terminal_packetization_initial_past_limit_does_not_encrypt() {
    assert!(exhausted_keys_emit_nothing(SpaceId::Initial, 1));
}

#[test]
fn terminal_packetization_handshake_past_limit_does_not_encrypt() {
    assert!(exhausted_keys_emit_nothing(SpaceId::Handshake, 1));
}

#[test]
fn terminal_packetization_initial_before_boundary_sends_crypto() {
    assert!(usable_keys_send_crypto(SpaceId::Initial));
}

#[test]
fn terminal_packetization_handshake_before_boundary_sends_crypto() {
    assert!(usable_keys_send_crypto(SpaceId::Handshake));
}
