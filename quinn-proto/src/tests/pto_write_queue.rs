use super::*;
use crate::packet::SpaceId;

#[derive(Debug)]
struct Packet {
    number: u64,
    frames: Vec<Frame>,
    payload: Vec<u8>,
    encrypted_bytes: usize,
    ciphertext: Vec<u8>,
    ecn: Option<EcnCodepoint>,
}

impl Packet {
    fn streams(&self) -> Vec<(StreamId, u64, Vec<u8>, bool)> {
        self.frames
            .iter()
            .filter_map(|frame| match frame {
                Frame::Stream(stream) => {
                    Some((stream.id, stream.offset, stream.data.to_vec(), stream.fin))
                }
                _ => None,
            })
            .collect()
    }
}

struct Case {
    pair: Pair,
    client: ConnectionHandle,
    server: ConnectionHandle,
}

impl Case {
    fn new(enabled: bool) -> Self {
        let mut server = server_config();
        let mut transport = TransportConfig::default();
        transport
            .mtu_discovery_config(None)
            .ack_obligation_only(true);
        server.transport_config(Arc::new(transport));
        let mut config = client_config_with_deterministic_pns();
        Arc::get_mut(&mut config.transport)
            .unwrap()
            .mtu_discovery_config(None)
            .ack_obligation_only(true)
            .pto_single_probe_with_gap(true)
            .queue_pto_while_blocked(enabled);
        let mut pair = Pair::new(Default::default(), server);
        let (client, server) = pair.connect_with(config);
        assert!(pair.client_conn_mut(client).pto_timing_for_test().confirmed);
        Self {
            pair,
            client,
            server,
        }
    }

    fn output(&mut self, blocked: bool, deliver: bool) -> Vec<Packet> {
        let now = self.pair.time;
        let mut result = Vec::new();
        let mut bytes = Vec::new();
        loop {
            let conn = self.pair.client_conn_mut(self.client);
            let transmit = if blocked {
                conn.poll_blocked_pto_transmit(now, &mut bytes)
            } else {
                conn.poll_transmit(now, 1, &mut bytes)
            };
            let Some(transmit) = transmit else { break };
            assert!(transmit.segment_size.is_none());
            assert_eq!(bytes[0] & 0x80, 0, "only real short-header packets qualify");
            let Some(DatagramEvent::ConnectionEvent(handle, event)) = self.pair.server.handle(
                now,
                self.pair.client.addr,
                None,
                transmit.ecn,
                BytesMut::from(&bytes[..transmit.size]),
                &mut Vec::new(),
            ) else {
                panic!("encrypted packet must route to real peer");
            };
            assert_eq!(handle, self.server);
            let (number, payload) = self
                .pair
                .server_conn_mut(self.server)
                .decode_packet_with_number(&event)
                .unwrap();
            result.push(Packet {
                number: number.unwrap(),
                frames: frame::Iter::new(payload.clone().into())
                    .unwrap()
                    .map(Result::unwrap)
                    .collect(),
                payload,
                encrypted_bytes: transmit.size,
                ciphertext: bytes[..transmit.size].to_vec(),
                ecn: transmit.ecn,
            });
            if deliver {
                self.pair.server_conn_mut(self.server).handle_event(event);
            }
            bytes.clear();
            if blocked {
                break;
            }
        }
        result
    }

    fn fire_pto(&mut self) {
        for _ in 0..4 {
            let conn = self.pair.client_conn_mut(self.client);
            let deadline = conn.loss_timeout_for_pto_test().unwrap();
            let lost = conn.stats().path.lost_packets;
            assert!(deadline >= self.pair.time);
            self.pair.time = deadline;
            let conn = self.pair.client_conn_mut(self.client);
            conn.handle_timeout(deadline);
            let credit = conn.pto_state_for_test(SpaceId::Data).1;
            if credit != 0 {
                assert_eq!(credit, 1);
                return;
            }
            // An ACK can schedule time-threshold loss before the next PTO.
            // Drive that real event without calling it a probe opportunity.
            assert!(
                conn.stats().path.lost_packets > lost,
                "a no-credit timer must have performed actual loss detection"
            );
        }
        panic!("no real PTO opportunity after bounded loss detection events");
    }

    fn ack(&mut self, number: u64) {
        let now = self.pair.time;
        let range = number..=number;
        self.pair
            .server_conn_mut(self.server)
            .queue_ack_for_pto_test(now, std::slice::from_ref(&range));
        let mut bytes = Vec::new();
        while let Some(transmit) = self
            .pair
            .server_conn_mut(self.server)
            .poll_transmit(now, 1, &mut bytes)
        {
            let Some(DatagramEvent::ConnectionEvent(handle, event)) = self.pair.client.handle(
                now,
                self.pair.server.addr,
                None,
                transmit.ecn,
                BytesMut::from(&bytes[..transmit.size]),
                &mut Vec::new(),
            ) else {
                panic!("real peer ACK must route to client");
            };
            assert_eq!(handle, self.client);
            self.pair.client_conn_mut(self.client).handle_event(event);
            bytes.clear();
        }
        assert!(!self.pair.client_conn_mut(self.client).is_closed());
    }

    fn stream(&mut self, bytes: &[u8], fin: bool) -> (StreamId, Packet) {
        let id = self
            .pair
            .client_streams(self.client)
            .open(Dir::Uni)
            .unwrap();
        if !bytes.is_empty() {
            self.pair.client_send(self.client, id).write(bytes).unwrap();
        }
        if fin {
            self.pair.client_send(self.client, id).finish().unwrap();
        }
        let mut packets = self.output(false, true);
        assert_eq!(packets.len(), 1);
        (id, packets.remove(0))
    }

    fn completed_bidi_request(&mut self) -> StreamId {
        let id = self.pair.client_streams(self.client).open(Dir::Bi).unwrap();
        self.pair
            .client_send(self.client, id)
            .write(b"request")
            .unwrap();
        self.pair.client_send(self.client, id).finish().unwrap();
        let request = self.output(false, true).remove(0);
        self.ack(request.number);
        id
    }
}

#[test]
fn pto_write_queue_proto_retransmits_selected_stream_without_new_payload() {
    let mut case = Case::new(true);
    let (id, original) = case.stream(b"old", false);
    case.pair
        .client_send(case.client, id)
        .write(b"/fresh tail")
        .unwrap();
    case.pair.client_send(case.client, id).finish().unwrap();
    let fresh = case
        .pair
        .client_streams(case.client)
        .open(Dir::Uni)
        .unwrap();
    case.pair
        .client_send(case.client, fresh)
        .write(b"fresh stream")
        .unwrap();
    case.pair.client_send(case.client, fresh).finish().unwrap();
    case.pair
        .client_datagrams(case.client)
        .send(Bytes::from_static(b"fresh datagram"), false)
        .unwrap();
    case.fire_pto();
    let probe = case.output(true, false);
    assert_eq!(probe.len(), 1);
    assert_eq!(
        probe[0].number,
        original.number + 2,
        "the real PTO reservation must skip exactly one PN"
    );
    assert_eq!(probe[0].streams(), vec![(id, 0, b"old".to_vec(), false)]);
    assert!(!probe[0].frames.iter().any(|frame| matches!(
        frame,
        Frame::Datagram(_) | Frame::PathChallenge(_) | Frame::PathResponse(_)
    )));
    assert!(
        !case
            .pair
            .client_conn_mut(case.client)
            .can_queue_pto_while_blocked()
    );
    let ordinary = case.output(false, true);
    let streams: Vec<_> = ordinary.iter().flat_map(Packet::streams).collect();
    assert!(streams.contains(&(id, 3, b"/fresh tail".to_vec(), true)));
    assert!(streams.contains(&(fresh, 0, b"fresh stream".to_vec(), true)));
    assert!(
        ordinary
            .iter()
            .flat_map(|packet| &packet.frames)
            .any(|frame| matches!(frame, Frame::Datagram(_)))
    );
}

#[test]
fn pto_write_queue_proto_empty_fin_is_a_real_probe() {
    for acknowledged_data in [false, true] {
        let mut case = Case::new(true);
        let (id, end) = if acknowledged_data {
            let (id, data) = case.stream(b"abc", false);
            case.pair.client_send(case.client, id).finish().unwrap();
            case.output(false, true);
            case.ack(data.number);
            (id, 3)
        } else {
            let (id, _) = case.stream(b"", true);
            (id, 0)
        };
        case.fire_pto();
        let packets = case.output(true, false);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].streams(), vec![(id, end, Vec::new(), true)]);
    }
}

#[test]
fn pto_write_queue_proto_partial_and_full_packets_preserve_stream_len_packing() {
    for payload_size in [128, 4096] {
        let mut case = Case::new(true);
        let id = case
            .pair
            .client_streams(case.client)
            .open(Dir::Uni)
            .unwrap();
        assert_eq!(
            case.pair
                .client_send(case.client, id)
                .write(&vec![0x5a; payload_size]),
            Ok(payload_size)
        );
        let originals = case.output(false, true);
        assert!(!originals.is_empty());
        let original = &originals[0];
        assert_eq!(
            original.payload[0] & 0xf8,
            0x08,
            "the first frame must be STREAM"
        );
        let full = payload_size == 4096;
        assert_eq!(original.payload[0] & 0x02 == 0, full);
        case.fire_pto();
        let probes = case.output(true, false);
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].number, originals.last().unwrap().number + 2);
        assert_eq!(probes[0].streams(), original.streams());
        assert_eq!(probes[0].payload[0] & 0x02, original.payload[0] & 0x02);
        assert_eq!(probes[0].encrypted_bytes, original.encrypted_bytes);
        assert_eq!(probes[0].encrypted_bytes == usize::from(INITIAL_MTU), full);
    }
}

#[test]
fn pto_write_queue_proto_required_ack_leaves_room_for_real_probe() {
    let mut case = Case::new(true);
    let (id, original) = case.stream(b"probe", false);
    case.fire_pto();
    let ranges: Vec<_> = (0..64)
        .map(|i| {
            let pn = i * (1u64 << 32);
            pn..=pn
        })
        .collect();
    let now = case.pair.time;
    case.pair
        .client_conn_mut(case.client)
        .queue_ack_for_pto_test(now, &ranges);
    let packets = case.output(true, false);
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].number, original.number + 2);
    assert!(
        packets[0]
            .frames
            .iter()
            .any(|frame| matches!(frame, Frame::Ack(_)))
    );
    assert!(packets[0].frames.iter().any(Frame::is_ack_eliciting));
    assert_eq!(
        packets[0].streams(),
        vec![(id, 0, b"probe".to_vec(), false)]
    );
}

#[test]
fn pto_write_queue_proto_ack_original_then_lose_copy_does_not_resurrect_bytes() {
    let mut case = Case::new(true);
    let (id, original) = case.stream(b"prefix", false);
    case.fire_pto();
    let copy = case.output(true, false).remove(0);
    assert_eq!(copy.streams(), vec![(id, 0, b"prefix".to_vec(), false)]);
    case.ack(original.number);
    let lost_before = case
        .pair
        .client_conn_mut(case.client)
        .stats()
        .path
        .lost_packets;
    let mut newest = copy.number;
    for _ in 0..3 {
        case.pair.client_conn_mut(case.client).ping();
        newest = case.output(false, true).last().unwrap().number;
    }
    case.ack(newest);
    assert!(
        case.pair
            .client_conn_mut(case.client)
            .stats()
            .path
            .lost_packets
            > lost_before,
        "the queued copy must actually be declared lost"
    );
    case.pair
        .client_send(case.client, id)
        .write(b"tail")
        .unwrap();
    case.pair.client_send(case.client, id).finish().unwrap();
    let packets = case.output(false, true);
    assert_eq!(
        packets.iter().flat_map(Packet::streams).collect::<Vec<_>>(),
        vec![(id, 6, b"tail".to_vec(), true)]
    );
}

#[test]
fn pto_write_queue_proto_partial_packet_ack_selects_only_remaining_stream_range() {
    let mut case = Case::new(true);
    let (id, first) = case.stream(b"abc", false);
    case.pair
        .client_send(case.client, id)
        .write(b"def")
        .unwrap();
    case.pair.client_send(case.client, id).finish().unwrap();
    let second = case.output(false, true).remove(0);
    case.ack(first.number);
    case.fire_pto();
    let probe = case.output(true, false);
    assert_eq!(probe.len(), 1);
    assert!(probe[0].number > second.number);
    assert_eq!(probe[0].streams(), vec![(id, 3, b"def".to_vec(), true)]);
}

#[test]
fn pto_write_queue_proto_reset_skips_discarded_payload_and_old_ack_retires_control() {
    let mut case = Case::new(true);
    let (id, _) = case.stream(b"discard", false);
    case.pair
        .client_send(case.client, id)
        .reset(268u32.into())
        .unwrap();
    let reset = case.output(false, true).remove(0);
    case.fire_pto();
    let probe = case.output(true, false);
    assert!(probe[0].streams().is_empty());
    assert!(probe[0].frames.iter().any(|frame| matches!(frame, Frame::ResetStream(reset) if reset.id == id && reset.error_code.into_inner() == 268 && reset.final_offset.into_inner() == 7)));
    case.ack(reset.number);
    case.fire_pto();
    let after = case.output(true, false);
    assert!(
        after
            .iter()
            .flat_map(|packet| &packet.frames)
            .all(|frame| !matches!(frame, Frame::Stream(_) | Frame::ResetStream(_)))
    );
}

#[test]
fn pto_write_queue_proto_disabled_and_no_credit_do_not_allocate_packets() {
    for enabled in [false, true] {
        let mut case = Case::new(enabled);
        let (id, _) = case.stream(b"pending", false);
        let before = case
            .pair
            .client_conn_mut(case.client)
            .pto_state_for_test(SpaceId::Data)
            .0;
        assert!(case.output(true, false).is_empty());
        assert_eq!(
            case.pair
                .client_conn_mut(case.client)
                .pto_state_for_test(SpaceId::Data)
                .0,
            before
        );
        if !enabled {
            case.fire_pto();
            let before = case
                .pair
                .client_conn_mut(case.client)
                .pto_state_for_test(SpaceId::Data)
                .0;
            assert!(case.output(true, false).is_empty());
            assert_eq!(
                case.pair
                    .client_conn_mut(case.client)
                    .pto_state_for_test(SpaceId::Data)
                    .0,
                before
            );
        }
        assert_eq!(case.pair.client_send(case.client, id).write(b"next"), Ok(4));
    }
}

#[test]
fn pto_write_queue_proto_unconfirmed_data_keys_do_not_qualify() {
    let mut config = client_config_with_deterministic_pns();
    Arc::get_mut(&mut config.transport)
        .unwrap()
        .queue_pto_while_blocked(true);
    let mut pair = Pair::default_with_deterministic_pns();
    let client = pair.begin_connect(config);
    pair.drive_client();
    pair.drive_server();
    while let Some((now, ecn, bytes)) = pair.client.inbound.pop_front() {
        let Some(DatagramEvent::ConnectionEvent(handle, event)) =
            pair.client
                .handle(now, pair.server.addr, None, ecn, bytes, &mut Vec::new())
        else {
            panic!("handshake must reach client");
        };
        assert_eq!(handle, client);
        pair.client_conn_mut(client).handle_event(event);
    }
    let snapshot = pair.client_conn_mut(client).pto_timing_for_test();
    assert!(snapshot.has_data_keys && !snapshot.confirmed);
    let before = pair
        .client_conn_mut(client)
        .pto_state_for_test(SpaceId::Data)
        .0;
    let now = pair.time;
    assert!(
        pair.client_conn_mut(client)
            .poll_blocked_pto_transmit(now, &mut Vec::new())
            .is_none()
    );
    assert_eq!(
        pair.client_conn_mut(client)
            .pto_state_for_test(SpaceId::Data)
            .0,
        before
    );
}

#[test]
fn pto_write_queue_proto_ack_original_stop_allows_committed_copy_but_no_new_copy() {
    let mut case = Case::new(true);
    let id = case.completed_bidi_request();
    case.pair
        .client_recv(case.client, id)
        .stop(268u32.into())
        .unwrap();
    let original = case.output(false, true).remove(0);
    let stop_count = |packet: &Packet| {
        packet.frames.iter().filter(|frame| {
        matches!(frame, Frame::StopSending(stop) if stop.id == id && stop.error_code.into_inner() == 268)
    }).count()
    };
    assert_eq!(stop_count(&original), 1);
    case.fire_pto();
    let queued = case.output(true, false).remove(0);
    assert_eq!(stop_count(&queued), 1);
    case.ack(original.number);

    // Completing this exact old ciphertext remains valid after original ACK.
    // Deliberately do not transmit the peer's resulting ACK of this copy yet.
    let before = case
        .pair
        .server_conn_mut(case.server)
        .stats()
        .frame_rx
        .stop_sending;
    let now = case.pair.time;
    let Some(DatagramEvent::ConnectionEvent(handle, event)) = case.pair.server.handle(
        now,
        case.pair.client.addr,
        None,
        queued.ecn,
        BytesMut::from(queued.ciphertext.as_slice()),
        &mut Vec::new(),
    ) else {
        panic!("committed ciphertext must still reach the peer");
    };
    assert_eq!(handle, case.server);
    let (number, _) = case
        .pair
        .server_conn_mut(case.server)
        .decode_packet_with_number(&event)
        .unwrap();
    assert_eq!(number, Some(queued.number));
    case.pair.server_conn_mut(case.server).handle_event(event);
    assert_eq!(
        case.pair
            .server_conn_mut(case.server)
            .stats()
            .frame_rx
            .stop_sending,
        before + 1
    );
    assert!(!case.pair.server_conn_mut(case.server).is_closed());

    case.fire_pto();
    let later = case.output(true, false);
    let newly_generated_stops: usize = later.iter().map(stop_count).sum();
    eprintln!(
        "STOP control ACK diagnostic: original_pn={} queued_pn={} committed_copy_received=1 later_packets={} newly_generated_stops={newly_generated_stops}",
        original.number,
        queued.number,
        later.len()
    );
    assert_eq!(
        newly_generated_stops, 0,
        "an ACKed control must not be selected for a new PTO copy, even though an already committed ciphertext copy remains deliverable"
    );
    assert!(
        later
            .iter()
            .flat_map(|packet| &packet.frames)
            .any(|frame| matches!(frame, Frame::Ping)),
        "with no eligible retransmission and no fresh work, the real credit must produce PING"
    );
    let lost = case
        .pair
        .client_conn_mut(case.client)
        .stats()
        .path
        .lost_packets;
    let mut newest = queued.number;
    for _ in 0..3 {
        case.pair.client_conn_mut(case.client).ping();
        newest = case.output(false, true).last().unwrap().number;
    }
    case.ack(newest);
    assert!(
        case.pair
            .client_conn_mut(case.client)
            .stats()
            .path
            .lost_packets
            > lost
    );
    assert_eq!(
        case.output(false, false)
            .iter()
            .map(stop_count)
            .sum::<usize>(),
        0,
        "losing an already committed copy must not requeue the ACKed STOP"
    );
}

#[test]
fn pto_write_queue_proto_ack_stop_copy_retires_the_original_metadata() {
    let mut case = Case::new(true);
    let id = case.completed_bidi_request();
    case.pair
        .client_recv(case.client, id)
        .stop(268u32.into())
        .unwrap();
    let original = case.output(false, true).remove(0);
    case.fire_pto();
    let copy = case.output(true, true).remove(0);
    assert!(copy.number > original.number);
    assert!(
        copy.frames
            .iter()
            .any(|frame| matches!(frame, Frame::StopSending(stop) if stop.id == id))
    );
    case.ack(copy.number);
    let after = case.output(false, false);
    assert!(
        !after
            .iter()
            .flat_map(|packet| &packet.frames)
            .any(|frame| matches!(frame, Frame::StopSending(stop) if stop.id == id)),
        "ACK of the copy must also retire or safely lose the older original"
    );
    assert!(
        case.output(true, false).is_empty(),
        "no timer credit may be invented after all eliciting packets are settled"
    );
}

#[test]
fn pto_write_queue_proto_stop_ack_keeps_other_stream_and_code_outstanding() {
    for other_code in [268u32, 269] {
        let mut case = Case::new(true);
        let id = case.completed_bidi_request();
        let other = case.completed_bidi_request();
        case.pair
            .client_recv(case.client, id)
            .stop(268u32.into())
            .unwrap();
        let original = case.output(false, true).remove(0);
        case.pair
            .client_recv(case.client, other)
            .stop(other_code.into())
            .unwrap();
        case.output(false, true);
        case.fire_pto();
        let copy = case.output(true, false).remove(0);
        assert!(
            copy.frames
                .iter()
                .any(|frame| matches!(frame, Frame::StopSending(stop) if stop.id == id))
        );
        case.ack(original.number);
        case.fire_pto();
        let later = case.output(true, false);
        let stops: Vec<_> = later
            .iter()
            .flat_map(|packet| &packet.frames)
            .filter_map(|frame| match frame {
                Frame::StopSending(stop) => Some((stop.id, stop.error_code.into_inner())),
                _ => None,
            })
            .collect();
        assert_eq!(stops, vec![(other, u64::from(other_code))]);
    }
}
