use super::*;
use crate::{packet::SpaceId, shared::ConnectionEventInner};
use std::{
    any::Any,
    sync::atomic::{AtomicUsize, Ordering},
};

#[derive(Debug)]
struct TicketStore {
    inner: Arc<rustls::server::ServerSessionMemoryCache>,
    take_hits: AtomicUsize,
}

impl TicketStore {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: rustls::server::ServerSessionMemoryCache::new(32),
            take_hits: AtomicUsize::new(0),
        })
    }
}

impl rustls::server::StoresServerSessions for TicketStore {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.inner.put(key, value)
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get(key)
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        let value = self.inner.take(key);
        if value.is_some() {
            self.take_hits.fetch_add(1, Ordering::SeqCst);
        }
        value
    }

    fn can_cache(&self) -> bool {
        self.inner.can_cache()
    }
}

// This decorator supplies the transport capability only for this fixed same-ALPN,
// shared-store fixture. Production rustls deliberately keeps the capability false.
struct AuthorizedConfig {
    inner: Arc<crypto::rustls::QuicClientConfig>,
    store: Arc<TicketStore>,
    authorize: bool,
    signal_rejection: bool,
}

impl crypto::ClientConfig for AuthorizedConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        let inner =
            crypto::ClientConfig::start_session(self.inner.clone(), version, server_name, params)?;
        let offered_early_data = inner.early_crypto().is_some();
        Ok(Box::new(AuthorizedSession {
            inner,
            store: self.store.clone(),
            authorize: self.authorize,
            offered_early_data,
            signal_rejection: self.signal_rejection,
        }))
    }
}

struct AuthorizedSession {
    inner: Box<dyn crypto::Session>,
    store: Arc<TicketStore>,
    authorize: bool,
    offered_early_data: bool,
    signal_rejection: bool,
}

impl crypto::Session for AuthorizedSession {
    fn initial_keys(&self, cid: &ConnectionId, side: Side) -> crypto::Keys {
        self.inner.initial_keys(cid, side)
    }
    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.inner.handshake_data()
    }
    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_identity()
    }
    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        self.inner.early_crypto()
    }
    fn early_data_accepted(&self) -> Option<bool> {
        self.inner.early_data_accepted()
    }
    fn early_data_rejected(&self) -> bool {
        // Contract control: an earlier explicit rejection must never be revived.
        self.signal_rejection && self.offered_early_data && !self.inner.is_handshaking()
    }
    fn early_data_rejection_allows_stream_reuse(&self) -> bool {
        self.authorize
            && self.offered_early_data
            && !self.inner.is_handshaking()
            && self.inner.early_data_accepted() == Some(false)
            && self.store.take_hits.load(Ordering::SeqCst) > 0
    }
    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }
    fn read_handshake(&mut self, bytes: &[u8]) -> Result<bool, TransportError> {
        self.inner.read_handshake(bytes)
    }
    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        self.inner.transport_parameters()
    }
    fn write_handshake(&mut self, bytes: &mut Vec<u8>) -> Option<crypto::Keys> {
        self.inner.write_handshake(bytes)
    }
    fn next_1rtt_keys(&mut self) -> Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>> {
        self.inner.next_1rtt_keys()
    }
    fn is_valid_retry(&self, cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.inner.is_valid_retry(cid, header, payload)
    }
    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), crypto::ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }
}

#[derive(Clone, Copy, Debug)]
enum LowerParameter {
    ConnectionIds,
    ConnectionData,
    BidiLocalData,
    BidiRemoteData,
    UniData,
    BidiStreams,
    UniStreams,
    Datagram,
    GreaseBit,
}

// Mutate the real server's TLS-encoded TP, not the client's parsed result. The
// server's application receive limits remain higher; these cases only test the
// client's decision to discard its early stream epoch after a legal reduction.
struct ServerParameters {
    inner: Arc<QuicServerConfig>,
    lower: Option<LowerParameter>,
    invalid_original_cid: bool,
}

impl crypto::ServerConfig for ServerParameters {
    fn initial_keys(
        &self,
        version: u32,
        cid: &ConnectionId,
    ) -> Result<crypto::Keys, crypto::UnsupportedVersion> {
        self.inner.initial_keys(version, cid)
    }
    fn retry_tag(&self, version: u32, cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        self.inner.retry_tag(version, cid, packet)
    }
    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        let mut params = params.clone();
        if self.invalid_original_cid {
            assert!(params.original_dst_cid.is_some_and(|cid| !cid.is_empty()));
            params.original_dst_cid = Some(ConnectionId::new(&[]));
        }
        let Some(lower) = self.lower else {
            return self.inner.clone().start_session(version, &params);
        };
        let limit = match lower {
            LowerParameter::ConnectionIds => &mut params.active_connection_id_limit,
            LowerParameter::ConnectionData => &mut params.initial_max_data,
            LowerParameter::BidiLocalData => &mut params.initial_max_stream_data_bidi_local,
            LowerParameter::BidiRemoteData => &mut params.initial_max_stream_data_bidi_remote,
            LowerParameter::UniData => &mut params.initial_max_stream_data_uni,
            LowerParameter::BidiStreams => &mut params.initial_max_streams_bidi,
            LowerParameter::UniStreams => &mut params.initial_max_streams_uni,
            LowerParameter::Datagram => params.max_datagram_frame_size.as_mut().unwrap(),
            LowerParameter::GreaseBit => {
                assert!(params.grease_quic_bit);
                params.grease_quic_bit = false;
                return self.inner.clone().start_session(version, &params);
            }
        };
        *limit = VarInt::from_u64(limit.into_inner().checked_sub(1).unwrap()).unwrap();
        self.inner.clone().start_session(version, &params)
    }
}

#[derive(Default)]
struct Options {
    accept: bool,
    signal_rejection: bool,
    grow_limits: bool,
    lower: Option<LowerParameter>,
    invalid_original_cid: bool,
}

#[derive(Debug)]
struct PacketObservation {
    number: u64,
    space: SpaceId,
    streams: Vec<(StreamId, u64, Bytes, bool)>,
    resets: Vec<(StreamId, VarInt, VarInt)>,
    stops: Vec<(StreamId, VarInt)>,
}

struct Fixture {
    pair: Pair,
    client: ConnectionHandle,
    store: Arc<TicketStore>,
    accepted: bool,
}

impl Fixture {
    fn new(enabled: bool, authorize: bool) -> Self {
        Self::configured(enabled, authorize, Options::default())
    }

    fn configured(enabled: bool, authorize: bool, options: Options) -> Self {
        let store = TicketStore::new();
        let mut tls = QuicServerConfig::inner(
            vec![CERTIFIED_KEY.cert.der().clone()],
            PrivateKeyDer::Pkcs8(CERTIFIED_KEY.signing_key.serialize_der().into()),
        )
        .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.max_early_data_size = u32::MAX;
        tls.session_storage = store.clone();
        let mut rejecting_tls = tls.clone();
        if !options.accept {
            rejecting_tls.max_early_data_size = 0;
        }
        let mut warm =
            ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
        if options.grow_limits {
            let mut transport = TransportConfig::default();
            transport
                .stream_receive_window(16u32.into())
                .receive_window(32u32.into());
            transport
                .max_concurrent_bidi_streams(2u32.into())
                .max_concurrent_uni_streams(2u32.into());
            warm.transport_config(Arc::new(transport));
        }
        let mut rejecting = warm.clone();
        let rejecting_crypto = Arc::new(QuicServerConfig::try_from(rejecting_tls).unwrap());
        rejecting.crypto = if options.lower.is_some() || options.invalid_original_cid {
            Arc::new(ServerParameters {
                inner: rejecting_crypto,
                lower: options.lower,
                invalid_original_cid: options.invalid_original_cid,
            })
        } else {
            rejecting_crypto
        };
        if options.grow_limits {
            let mut transport = TransportConfig::default();
            transport
                .stream_receive_window(64u32.into())
                .receive_window(128u32.into());
            transport
                .max_concurrent_bidi_streams(3u32.into())
                .max_concurrent_uni_streams(3u32.into());
            rejecting.transport_config(Arc::new(transport));
        }
        let mut pair = Pair::new(Arc::new(EndpointConfig::default()), warm);
        let crypto = Arc::new(AuthorizedConfig {
            inner: Arc::new(client_crypto_with_alpn(vec![b"h3".to_vec()])),
            store: store.clone(),
            authorize,
            signal_rejection: options.signal_rejection,
        });
        let mut config = ClientConfig::new(crypto);
        let mut transport = TransportConfig::default();
        transport.reuse_rejected_0rtt_streams(enabled);
        transport.deterministic_packet_numbers(true);
        transport.mtu_discovery_config(None);
        config.transport_config(Arc::new(transport));
        let (warm_client, _) = pair.connect_with(config.clone());
        let now = pair.time;
        pair.client_conn_mut(warm_client)
            .close(now, 0u32.into(), Bytes::new());
        pair.drive();
        pair.client.connections.clear();
        pair.server.connections.clear();
        pair.server.set_server_config(Some(Arc::new(rejecting)));
        let client = pair.begin_connect(config);
        assert!(
            pair.client_conn_mut(client).has_0rtt(),
            "real cached early keys are required"
        );
        assert_eq!(store.take_hits.load(Ordering::SeqCst), 0);
        Self {
            pair,
            client,
            store,
            accepted: options.accept,
        }
    }

    fn finish_handshake(&mut self) -> ConnectionHandle {
        self.pair.drive();
        let server = self.pair.server.assert_accept();
        assert!(!self.pair.client_conn_mut(self.client).is_handshaking());
        assert_eq!(
            self.pair.client_conn_mut(self.client).accepted_0rtt(),
            self.accepted
        );
        assert_eq!(
            self.store.take_hits.load(Ordering::SeqCst),
            1,
            "the real server must consume the cached PSK"
        );
        assert_eq!(
            self.pair.server.connections.len(),
            1,
            "recovery must stay on this connection"
        );
        server
    }

    fn finish_client_without_transmitting(&mut self) -> ConnectionHandle {
        self.pair.drive_server();
        let server = self.pair.server.assert_accept();
        while let Some((at, ecn, bytes)) = self.pair.client.inbound.pop_front() {
            let Some(DatagramEvent::ConnectionEvent(handle, event)) = self.pair.client.handle(
                at,
                self.pair.server.addr,
                None,
                ecn,
                bytes,
                &mut Vec::new(),
            ) else {
                panic!("real handshake datagram must reach the existing client");
            };
            assert_eq!(handle, self.client);
            self.pair.client_conn_mut(self.client).handle_event(event);
        }
        assert!(!self.pair.client_conn_mut(self.client).is_handshaking());
        assert!(
            self.pair
                .client_conn_mut(self.client)
                .rejected_0rtt_streams_reused()
        );
        assert_eq!(self.store.take_hits.load(Ordering::SeqCst), 1);
        server
    }

    fn client_packets(
        &mut self,
        server: ConnectionHandle,
        drop_stream_packets: bool,
    ) -> Vec<PacketObservation> {
        let mut packets = Vec::new();
        let now = self.pair.time;
        let mut buffer = Vec::new();
        while let Some(transmit) =
            self.pair
                .client_conn_mut(self.client)
                .poll_transmit(now, 1, &mut buffer)
        {
            assert!(transmit.segment_size.is_none());
            let mut remaining = Some(BytesMut::from(&buffer[..transmit.size]));
            while let Some(bytes) = remaining {
                let Some(DatagramEvent::ConnectionEvent(handle, mut event)) =
                    self.pair.server.handle(
                        now,
                        self.pair.client.addr,
                        None,
                        transmit.ecn,
                        bytes,
                        &mut Vec::new(),
                    )
                else {
                    panic!("encrypted output must route to the real server");
                };
                assert_eq!(handle, server);
                let ConnectionEventInner::Datagram(datagram) = &mut event.0 else {
                    unreachable!()
                };
                let space = datagram.first_decode.space().unwrap();
                remaining = datagram.remaining.take();
                let (number, payload) = self
                    .pair
                    .server_conn_mut(server)
                    .decode_packet_with_number(&event)
                    .unwrap();
                let mut packet = PacketObservation {
                    number: number.unwrap(),
                    space,
                    streams: Vec::new(),
                    resets: Vec::new(),
                    stops: Vec::new(),
                };
                for frame in frame::Iter::new(payload.into()).unwrap() {
                    match frame.unwrap() {
                        Frame::Stream(stream) => {
                            packet
                                .streams
                                .push((stream.id, stream.offset, stream.data, stream.fin))
                        }
                        Frame::ResetStream(reset) => {
                            packet
                                .resets
                                .push((reset.id, reset.error_code, reset.final_offset))
                        }
                        Frame::StopSending(stop) => packet.stops.push((stop.id, stop.error_code)),
                        _ => (),
                    }
                }
                if !drop_stream_packets || packet.streams.is_empty() {
                    self.pair.server_conn_mut(server).handle_event(event);
                }
                packets.push(packet);
            }
            buffer.clear();
        }
        packets
    }

    fn read_all(&mut self, server: ConnectionHandle, stream: StreamId) -> Vec<u8> {
        let mut recv = self.pair.server_recv(server, stream);
        let mut chunks = recv.read(true).unwrap();
        let mut bytes = Vec::new();
        while let Some(chunk) = chunks.next(usize::MAX).unwrap() {
            bytes.extend_from_slice(&chunk.bytes);
        }
        let _ = chunks.finalize();
        bytes
    }
}

#[test]
fn zero_rtt_reuse_sent_data_and_fin_keep_the_original_stream() {
    let _guard = subscribe();
    let mut fixture = Fixture::new(true, true);
    let stream = fixture
        .pair
        .client_streams(fixture.client)
        .open(Dir::Bi)
        .unwrap();
    fixture
        .pair
        .client_send(fixture.client, stream)
        .write(b"retained early request")
        .unwrap();
    fixture
        .pair
        .client_send(fixture.client, stream)
        .finish()
        .unwrap();
    fixture.pair.drive_client();
    let server = fixture.finish_handshake();
    assert!(
        fixture
            .pair
            .client_conn_mut(fixture.client)
            .rejected_0rtt_streams_reused(),
        "authorized compatible rejection must retain the original stream epoch"
    );
    assert_eq!(fixture.read_all(server, stream), b"retained early request");
    let next = fixture
        .pair
        .client_streams(fixture.client)
        .open(Dir::Bi)
        .unwrap();
    assert_eq!(next, StreamId::new(Side::Client, Dir::Bi, 1));
}

#[test]
fn zero_rtt_reuse_default_off_keeps_legacy_discard() {
    let _guard = subscribe();
    let mut fixture = Fixture::new(false, true);
    let stream = fixture
        .pair
        .client_streams(fixture.client)
        .open(Dir::Uni)
        .unwrap();
    fixture
        .pair
        .client_send(fixture.client, stream)
        .write(b"discard")
        .unwrap();
    let server = fixture.finish_handshake();
    assert!(
        !fixture
            .pair
            .client_conn_mut(fixture.client)
            .rejected_0rtt_streams_reused()
    );
    let replacement = fixture
        .pair
        .client_streams(fixture.client)
        .open(Dir::Uni)
        .unwrap();
    assert_eq!(replacement, stream);
    fixture
        .pair
        .client_send(fixture.client, replacement)
        .write(b"replacement")
        .unwrap();
    fixture
        .pair
        .client_send(fixture.client, replacement)
        .finish()
        .unwrap();
    fixture.pair.drive();
    assert_eq!(fixture.read_all(server, replacement), b"replacement");
}

#[test]
fn zero_rtt_reuse_missing_crypto_authority_keeps_legacy_discard() {
    let _guard = subscribe();
    let mut fixture = Fixture::new(true, false);
    let stream = fixture
        .pair
        .client_streams(fixture.client)
        .open(Dir::Uni)
        .unwrap();
    fixture
        .pair
        .client_send(fixture.client, stream)
        .write(b"discard")
        .unwrap();
    fixture.finish_handshake();
    assert!(
        !fixture
            .pair
            .client_conn_mut(fixture.client)
            .rejected_0rtt_streams_reused()
    );
    assert_eq!(
        fixture.pair.client_streams(fixture.client).open(Dir::Uni),
        Some(stream)
    );
}

#[test]
fn zero_rtt_reuse_sent_and_pending_bytes_preserve_offsets_and_fin() {
    let _guard = subscribe();
    let mut fixture = Fixture::new(true, true);
    let stream = fixture
        .pair
        .client_streams(fixture.client)
        .open(Dir::Bi)
        .unwrap();
    fixture
        .pair
        .client_send(fixture.client, stream)
        .write(b"sent prefix/")
        .unwrap();
    fixture.pair.drive_client();
    fixture
        .pair
        .client_send(fixture.client, stream)
        .write(b"pending suffix")
        .unwrap();
    fixture
        .pair
        .client_send(fixture.client, stream)
        .finish()
        .unwrap();
    let server = fixture.finish_client_without_transmitting();
    let packets = fixture.client_packets(server, false);
    assert!(packets.iter().any(|packet| {
        packet.space == SpaceId::Data
            && packet
                .streams
                .iter()
                .any(|frame| frame.0 == stream && frame.3)
    }));
    fixture.pair.drive();
    assert_eq!(
        fixture.read_all(server, stream),
        b"sent prefix/pending suffix"
    );
    assert_eq!(
        fixture.pair.client_streams(fixture.client).send_streams(),
        0,
        "normal ACKs must release the retained send buffer"
    );
}

#[test]
fn zero_rtt_reuse_empty_fin_survives_sent_and_pending_states() {
    let _guard = subscribe();
    for packetized in [false, true] {
        let mut fixture = Fixture::new(true, true);
        fixture.pair.drive_client();
        let stream = fixture
            .pair
            .client_streams(fixture.client)
            .open(Dir::Uni)
            .unwrap();
        fixture
            .pair
            .client_send(fixture.client, stream)
            .finish()
            .unwrap();
        if packetized {
            fixture.pair.drive_client();
        }
        let server = fixture.finish_client_without_transmitting();
        let packets = fixture.client_packets(server, false);
        let fin = packets
            .iter()
            .flat_map(|packet| &packet.streams)
            .find(|frame| frame.0 == stream)
            .expect("empty FIN must be retransmitted even without byte ranges");
        assert_eq!((fin.1, fin.2.len(), fin.3), (0, 0, true));
        fixture.pair.drive();
        assert!(fixture.read_all(server, stream).is_empty());
        assert_eq!(
            fixture.pair.client_streams(fixture.client).send_streams(),
            0
        );
    }
}

#[test]
fn zero_rtt_reuse_reset_and_stop_keep_codes_without_resurrecting_payload() {
    let _guard = subscribe();
    for (data_packetized, reset_packetized) in
        [(false, false), (false, true), (true, false), (true, true)]
    {
        let mut fixture = Fixture::new(true, true);
        fixture.pair.drive_client();
        let stream = fixture
            .pair
            .client_streams(fixture.client)
            .open(Dir::Bi)
            .unwrap();
        fixture
            .pair
            .client_send(fixture.client, stream)
            .write(b"discard")
            .unwrap();
        if data_packetized {
            fixture.pair.drive_client();
        }
        fixture
            .pair
            .client_send(fixture.client, stream)
            .reset(256u32.into())
            .unwrap();
        fixture
            .pair
            .client_recv(fixture.client, stream)
            .stop(268u32.into())
            .unwrap();
        if reset_packetized {
            fixture.pair.drive_client();
        }
        let server = fixture.finish_client_without_transmitting();
        let packets = fixture.client_packets(server, false);
        assert!(
            packets
                .iter()
                .all(|packet| packet.streams.iter().all(|frame| frame.0 != stream)),
            "reset data must remain discarded: {packets:?}"
        );
        let resets: Vec<_> = packets
            .iter()
            .flat_map(|packet| &packet.resets)
            .copied()
            .collect();
        assert_eq!(resets, vec![(stream, 256u32.into(), 7u32.into())]);
        let stops: Vec<_> = packets
            .iter()
            .flat_map(|packet| &packet.stops)
            .copied()
            .collect();
        assert_eq!(stops, vec![(stream, 268u32.into())]);
        fixture.pair.drive();
        let mut recv = fixture.pair.server_recv(server, stream);
        let mut chunks = recv.read(true).unwrap();
        assert_eq!(
            chunks.next(usize::MAX),
            Err(ReadError::Reset(256u32.into()))
        );
        let _ = chunks.finalize();
    }
}

#[test]
fn zero_rtt_reuse_lost_one_rtt_copy_recovers_and_releases_send_state() {
    let _guard = subscribe();
    let mut fixture = Fixture::new(true, true);
    let stream = fixture
        .pair
        .client_streams(fixture.client)
        .open(Dir::Uni)
        .unwrap();
    fixture
        .pair
        .client_send(fixture.client, stream)
        .write(b"retransmit after rejection")
        .unwrap();
    fixture
        .pair
        .client_send(fixture.client, stream)
        .finish()
        .unwrap();
    fixture.pair.drive_client();
    let server = fixture.finish_client_without_transmitting();
    let dropped = fixture.client_packets(server, true);
    assert!(
        dropped
            .iter()
            .any(|packet| packet.space == SpaceId::Data && !packet.streams.is_empty()),
        "drop an authenticated 1-RTT stream packet, not the handshake"
    );
    assert!(!fixture.pair.server_conn_mut(server).is_handshaking());
    fixture.pair.drive();
    assert_eq!(
        fixture.read_all(server, stream),
        b"retransmit after rejection"
    );
    assert_eq!(
        fixture.pair.client_streams(fixture.client).send_streams(),
        0
    );
    assert!(!fixture.pair.client_conn_mut(fixture.client).is_closed());
}

#[test]
fn zero_rtt_reuse_old_ack_is_rejected_before_freeing_valid_one_rtt_state() {
    let _guard = subscribe();
    let mut fixture = Fixture::new(true, true);
    let stream = fixture
        .pair
        .client_streams(fixture.client)
        .open(Dir::Uni)
        .unwrap();
    fixture
        .pair
        .client_send(fixture.client, stream)
        .write(b"unacknowledged")
        .unwrap();
    fixture
        .pair
        .client_send(fixture.client, stream)
        .finish()
        .unwrap();
    fixture.pair.drive_client();
    let server = fixture.finish_client_without_transmitting();
    let boundary = fixture
        .pair
        .client_conn_mut(fixture.client)
        .pto_timing_for_test()
        .first_1rtt_boundary
        .unwrap();
    assert!(boundary > 0, "the fixture must have emitted actual 0-RTT");
    let packets = fixture.client_packets(server, false);
    let newest = packets
        .iter()
        .filter(|packet| packet.space == SpaceId::Data)
        .map(|packet| packet.number)
        .max()
        .unwrap();
    assert!(newest >= boundary);
    assert!(
        !fixture
            .pair
            .client_conn_mut(fixture.client)
            .pto_timing_for_test()
            .data_acknowledged
    );
    let now = fixture.pair.time;
    let range = 0..=newest;
    fixture
        .pair
        .server_conn_mut(server)
        .queue_ack_for_pto_test(now, std::slice::from_ref(&range));
    fixture.pair.drive_server();
    fixture.pair.drive_client();
    assert!(std::iter::from_fn(|| fixture.pair.client_conn_mut(fixture.client).poll()).any(|event| {
        matches!(event, Event::ConnectionLost { reason: ConnectionError::TransportError(error) }
            if error.code == TransportErrorCode::PROTOCOL_VIOLATION && error.reason == "rejected 0-RTT packet acked")
    }));
    assert!(
        !fixture
            .pair
            .client_conn_mut(fixture.client)
            .pto_timing_for_test()
            .data_acknowledged,
        "invalid ranges must precede largest-ACK mutation"
    );
    assert_eq!(
        fixture.pair.client_streams(fixture.client).send_streams(),
        1,
        "the valid 1-RTT part of the forged ACK must not free its retained stream"
    );
    assert!(
        fixture
            .pair
            .client_conn_mut(fixture.client)
            .rejected_0rtt_streams_reused(),
        "late closure must not erase the historical retained epoch"
    );
}

#[test]
fn zero_rtt_reuse_expanded_credit_updates_existing_local_streams() {
    let _guard = subscribe();
    let mut fixture = Fixture::configured(
        true,
        true,
        Options {
            grow_limits: true,
            ..Options::default()
        },
    );
    let bi = fixture
        .pair
        .client_streams(fixture.client)
        .open(Dir::Bi)
        .unwrap();
    let uni = fixture
        .pair
        .client_streams(fixture.client)
        .open(Dir::Uni)
        .unwrap();
    for stream in [bi, uni] {
        assert_eq!(
            fixture
                .pair
                .client_send(fixture.client, stream)
                .write(&[1; 16]),
            Ok(16)
        );
        assert_eq!(
            fixture.pair.client_send(fixture.client, stream).write(&[2]),
            Err(WriteError::Blocked)
        );
    }
    fixture.pair.drive_client();
    let server = fixture.finish_client_without_transmitting();
    let events: Vec<_> =
        std::iter::from_fn(|| fixture.pair.client_conn_mut(fixture.client).poll()).collect();
    for stream in [bi, uni] {
        assert!(events.iter().any(|event| matches!(event, Event::Stream(StreamEvent::Writable { id }) if *id == stream)), "no writable event for {stream}: {events:?}");
        assert_eq!(
            fixture
                .pair
                .client_send(fixture.client, stream)
                .write(&[2; 32]),
            Ok(32),
            "fresh limits must apply before peer application reads anything"
        );
        fixture
            .pair
            .client_send(fixture.client, stream)
            .finish()
            .unwrap();
    }
    for dir in [Dir::Bi, Dir::Uni] {
        let next = fixture
            .pair
            .client_streams(fixture.client)
            .open(dir)
            .unwrap();
        assert_eq!(next, StreamId::new(Side::Client, dir, 1));
        if dir == Dir::Bi {
            assert_eq!(
                fixture
                    .pair
                    .client_send(fixture.client, next)
                    .write(&[3; 32]),
                Ok(32)
            );
            assert_eq!(
                fixture.pair.client_send(fixture.client, next).write(&[3]),
                Err(WriteError::Blocked),
                "old 32 bytes and new 96 bytes must consume exactly the fresh 128-byte connection credit"
            );
            fixture
                .pair
                .client_send(fixture.client, next)
                .finish()
                .unwrap();
        }
        assert_eq!(
            fixture.pair.client_streams(fixture.client).open(dir),
            Some(StreamId::new(Side::Client, dir, 2))
        );
        assert_eq!(fixture.pair.client_streams(fixture.client).open(dir), None);
    }
    fixture.pair.drive();
    for stream in [bi, uni] {
        assert_eq!(
            fixture.read_all(server, stream),
            [&[1; 16][..], &[2; 32][..]].concat()
        );
    }
}

#[test]
fn zero_rtt_reuse_each_decreased_parameter_keeps_legacy_discard() {
    let _guard = subscribe();
    for lower in [
        LowerParameter::ConnectionIds,
        LowerParameter::ConnectionData,
        LowerParameter::BidiLocalData,
        LowerParameter::BidiRemoteData,
        LowerParameter::UniData,
        LowerParameter::BidiStreams,
        LowerParameter::UniStreams,
        LowerParameter::Datagram,
        LowerParameter::GreaseBit,
    ] {
        let mut fixture = Fixture::configured(
            true,
            true,
            Options {
                lower: Some(lower),
                ..Options::default()
            },
        );
        let stream = fixture
            .pair
            .client_streams(fixture.client)
            .open(Dir::Uni)
            .unwrap();
        fixture
            .pair
            .client_send(fixture.client, stream)
            .write(b"discard")
            .unwrap();
        fixture
            .pair
            .client_send(fixture.client, stream)
            .finish()
            .unwrap();
        fixture.pair.drive_client();
        let server = fixture.finish_handshake();
        assert!(
            !fixture
                .pair
                .client_conn_mut(fixture.client)
                .rejected_0rtt_streams_reused(),
            "lower {lower:?} must not retain cached credit"
        );
        assert!(
            !fixture.pair.client_conn_mut(fixture.client).is_closed(),
            "legal rejected-0RTT TP reductions are not protocol violations"
        );
        assert_eq!(
            fixture.pair.client_streams(fixture.client).open(Dir::Uni),
            Some(stream)
        );
        fixture
            .pair
            .client_send(fixture.client, stream)
            .write(b"new")
            .unwrap();
        fixture
            .pair
            .client_send(fixture.client, stream)
            .finish()
            .unwrap();
        fixture.pair.drive();
        assert_eq!(fixture.read_all(server, stream), b"new");
    }
}

#[test]
fn zero_rtt_reuse_earlier_rejection_cannot_be_revived() {
    let _guard = subscribe();
    let mut fixture = Fixture::configured(
        true,
        true,
        Options {
            signal_rejection: true,
            ..Options::default()
        },
    );
    let stream = fixture
        .pair
        .client_streams(fixture.client)
        .open(Dir::Uni)
        .unwrap();
    fixture
        .pair
        .client_send(fixture.client, stream)
        .write(b"discard")
        .unwrap();
    fixture.finish_handshake();
    assert!(
        !fixture
            .pair
            .client_conn_mut(fixture.client)
            .rejected_0rtt_streams_reused()
    );
    assert_eq!(
        fixture.pair.client_streams(fixture.client).open(Dir::Uni),
        Some(stream)
    );
}

#[test]
fn zero_rtt_reuse_accepted_early_data_remains_acceptance_not_reuse() {
    let _guard = subscribe();
    let mut fixture = Fixture::configured(
        true,
        true,
        Options {
            accept: true,
            ..Options::default()
        },
    );
    let stream = fixture
        .pair
        .client_streams(fixture.client)
        .open(Dir::Uni)
        .unwrap();
    fixture
        .pair
        .client_send(fixture.client, stream)
        .write(b"accepted")
        .unwrap();
    fixture
        .pair
        .client_send(fixture.client, stream)
        .finish()
        .unwrap();
    let server = fixture.finish_handshake();
    assert!(fixture.pair.client_conn_mut(fixture.client).accepted_0rtt());
    assert!(
        !fixture
            .pair
            .client_conn_mut(fixture.client)
            .rejected_0rtt_streams_reused()
    );
    assert_eq!(fixture.read_all(server, stream), b"accepted");
}

#[test]
fn zero_rtt_reuse_invalid_authenticated_cid_never_latches_retention() {
    let _guard = subscribe();
    let mut fixture = Fixture::configured(
        true,
        true,
        Options {
            invalid_original_cid: true,
            ..Options::default()
        },
    );
    let stream = fixture
        .pair
        .client_streams(fixture.client)
        .open(Dir::Uni)
        .unwrap();
    fixture
        .pair
        .client_send(fixture.client, stream)
        .write(b"retain only after valid TP")
        .unwrap();
    fixture.pair.drive();
    assert_eq!(fixture.store.take_hits.load(Ordering::SeqCst), 1);
    assert!(
        !fixture
            .pair
            .client_conn_mut(fixture.client)
            .crypto_session()
            .is_handshaking(),
        "TLS must complete before the CID consistency check"
    );
    assert!(
        !fixture
            .pair
            .client_conn_mut(fixture.client)
            .rejected_0rtt_streams_reused()
    );
    let events: Vec<_> =
        std::iter::from_fn(|| fixture.pair.client_conn_mut(fixture.client).poll()).collect();
    assert!(!events.iter().any(|event| matches!(event, Event::Connected)));
    assert!(
        events.iter().any(|event| matches!(event,
            Event::ConnectionLost { reason: ConnectionError::TransportError(error) }
            if error.code == TransportErrorCode::TRANSPORT_PARAMETER_ERROR
        )),
        "CID validation must retain its real transport error: {events:?}"
    );
}
