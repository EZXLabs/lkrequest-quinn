use super::*;

fn chaos_config(extra_hello_bytes: usize, gso: bool) -> ClientConfig {
    chaos_config_with_mtu(extra_hello_bytes, gso, 1500)
}

fn chaos_config_with_mtu(extra_hello_bytes: usize, gso: bool, mtu: u16) -> ClientConfig {
    let mut transport = TransportConfig::default();
    transport
        .initial_packet_chaos(true)
        .initial_mtu(mtu)
        .initial_datagram_size(1250)
        .enable_segmentation_offload(gso)
        .extra_transport_parameters(vec![(
            VarInt::from_u32(0x173e),
            vec![42; extra_hello_bytes],
        )])
        .unwrap();
    let mut config = client_config();
    config.transport_config(Arc::new(transport));
    config
}

fn assert_connected(pair: &mut Pair, client: ConnectionHandle) -> ConnectionHandle {
    assert!(!pair.drive_bounded(), "handshake failed to settle");
    assert_matches!(
        pair.client_conn_mut(client).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(pair.client_conn_mut(client).poll(), Some(Event::Connected));
    let server = pair.server.assert_accept();
    assert_matches!(
        pair.server_conn_mut(server).poll(),
        Some(Event::HandshakeDataReady)
    );
    assert_matches!(pair.server_conn_mut(server).poll(), Some(Event::Connected));
    server
}

#[test]
fn initial_chaos_handshake_variable_hello_and_datagram_size() {
    let _guard = subscribe();
    for extra_bytes in [0, 1300, 3000, 12000] {
        for gso in [false, true] {
            for mtu in [1250, 1350, 1472, 1500] {
                let mut pair = Pair::default();
                pair.mtu = 1500;
                let client = pair.begin_connect(chaos_config_with_mtu(extra_bytes, gso, mtu));
                pair.drive_client();
                assert!(!pair.server.inbound.is_empty());
                for (_, _, bytes) in &pair.server.inbound {
                    assert_eq!(bytes.len(), 1250);
                }
                if extra_bytes >= 1300 {
                    assert!(pair.server.inbound.len() >= 2);
                }
                assert_connected(&mut pair, client);
                assert!(pair.client_conn_mut(client).stats().frame_tx.ping >= 2);
            }
        }
    }
}

#[test]
fn initial_chaos_handshake_recovers_from_initial_loss() {
    let _guard = subscribe();
    for drop_first in [false, true] {
        let mut pair = Pair::default();
        let client = pair.begin_connect(chaos_config(3000, true));
        pair.drive_client();
        assert!(pair.server.inbound.len() >= 3);
        if drop_first {
            pair.server.inbound.pop_front().unwrap();
        } else {
            pair.server.inbound.pop_back().unwrap();
        }
        assert_connected(&mut pair, client);
    }
}

#[test]
fn initial_chaos_handshake_recovers_from_whole_flight_loss() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let client = pair.begin_connect(chaos_config(3000, false));
    pair.drive_client();
    assert!(pair.server.inbound.len() >= 3);
    pair.server.inbound.clear();
    assert_connected(&mut pair, client);
}

#[test]
fn initial_chaos_retry_rebuilds_layout_with_token_header() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    pair.server.handle_incoming = Box::new(validate_incoming);
    let client = pair.begin_connect(chaos_config(3000, true));
    pair.drive_client();
    assert!(pair.server.inbound.len() >= 3);
    pair.drive_server();
    assert!(!pair.client.inbound.is_empty());
    assert!(pair.server.connections.is_empty());
    pair.drive_client();
    assert!(pair.server.inbound.len() >= 3);
    for (_, _, bytes) in &pair.server.inbound {
        assert_eq!(bytes.len(), 1250);
    }
    assert_connected(&mut pair, client);
}

#[test]
fn initial_chaos_retry_token_larger_than_target_uses_available_mtu() {
    use crate::{
        crypto::ServerConfig as _,
        packet::{FixedLengthConnectionIdParser, Header, PartialDecode},
    };

    let _guard = subscribe();
    let mut pair = Pair::default();
    pair.mtu = 9000;
    let client = pair.begin_connect(chaos_config_with_mtu(3000, true, 9000));
    pair.drive_client();
    let first = pair.server.inbound.pop_front().unwrap().2;
    let (initial, _) =
        PartialDecode::new(first, &FixedLengthConnectionIdParser::new(8), &[1], true).unwrap();
    let initial = initial.initial_header().unwrap();
    let retry_cid = ConnectionId::new(&[42; 8]);
    let mut retry = Vec::new();
    Header::Retry {
        src_cid: retry_cid,
        dst_cid: initial.src_cid,
        version: 1,
    }
    .encode(&mut retry);
    retry.extend_from_slice(&vec![42; 2000]);
    let server_crypto = server_crypto();
    retry.extend_from_slice(&server_crypto.retry_tag(1, &initial.dst_cid, &retry));
    pair.server.inbound.clear();
    pair.client
        .inbound
        .push_back((pair.time, None, BytesMut::from(retry.as_slice())));
    let crypto_before = pair.client_conn_mut(client).stats().frame_tx.crypto;
    pair.drive_client();
    assert_eq!(pair.server.inbound.len(), 1);
    assert_eq!(pair.server.inbound[0].2.len(), 9000);
    assert!(pair.client_conn_mut(client).stats().frame_tx.crypto > crypto_before);
    let (after, rest) = PartialDecode::new(
        pair.server.inbound[0].2.clone(),
        &FixedLengthConnectionIdParser::new(8),
        &[1],
        true,
    )
    .unwrap();
    assert!(rest.is_none());
    assert_eq!(after.initial_header().unwrap().dst_cid, retry_cid);
}

#[test]
fn initial_chaos_zero_rtt_preserves_application_data() {
    let _guard = subscribe();
    for retry in [false, true] {
        initial_chaos_zero_rtt(retry);
    }
}

fn initial_chaos_zero_rtt(retry: bool) {
    let mut pair = Pair::default();
    pair.server.handle_incoming = Box::new(validate_incoming);
    let config = chaos_config(3000, true);
    let client = pair.begin_connect(config.clone());
    assert_connected(&mut pair, client);
    let now = pair.time;
    pair.client_conn_mut(client)
        .close(now, VarInt(0), Bytes::new());
    pair.drive();

    if retry {
        pair.client
            .addr
            .set_port(CLIENT_PORTS.lock().unwrap().next().unwrap());
    }
    let client = pair.begin_connect(config);
    assert!(pair.client_conn_mut(client).has_0rtt());
    let stream = pair.client_streams(client).open(Dir::Uni).unwrap();
    const MESSAGE: &[u8] = b"application data survives chaotic Initial frames";
    pair.client_send(client, stream).write(MESSAGE).unwrap();
    let server = assert_connected(&mut pair, client);
    assert!(pair.client_conn_mut(client).accepted_0rtt());
    let mut recv = pair.server_recv(server, stream);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(chunks.next(usize::MAX), Ok(Some(chunk)) if chunk.offset == 0 && chunk.bytes == MESSAGE);
    let _ = chunks.finalize();
}
