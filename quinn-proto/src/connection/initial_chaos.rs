// Copyright (c) 2012, 2021 The Chromium Authors. All rights reserved.
// Copyright (c) 2026 The lkrequest contributors.
//
// Adapted from quic_chaos_protector.cc and quic_packet_creator.cc at
// google/quiche 2c4a124642f095f995cd2e9e2fe10decc08df662.
// Use of the Chromium source is governed by the BSD-style license in
// LICENSE-CHROMIUM in this crate.

use std::collections::VecDeque;

use bytes::Bytes;
use rand::Rng;

use super::{ConnectionStats, SentFrames};
use crate::{Frame, VarInt, coding::BufMutExt, frame};

enum Element {
    Crypto(frame::Crypto),
    Ping,
    Padding(usize),
    Preserved { bytes: Bytes, ack: bool },
}

pub(super) fn populate_packet(
    pending: &mut VecDeque<frame::Crypto>,
    buf: &mut Vec<u8>,
    max_size: usize,
    packet_payload_start: usize,
    rng: &mut impl Rng,
    sent: &mut SentFrames,
    stats: &mut ConnectionStats,
) -> bool {
    let budget = max_size.saturating_sub(buf.len());
    let Some(mut frames) = preserve_prefix(&buf[packet_payload_start..]) else {
        return false;
    };
    let mut crypto_frames = take_crypto(
        pending,
        budget,
        max_size.saturating_sub(packet_payload_start),
        rng,
    );
    if crypto_frames.is_empty() {
        return false;
    }
    let padding = budget - encoded_size(&crypto_frames);
    frames.append(&mut crypto_frames);
    if padding > 0 {
        protect(&mut frames, padding, rng);
    }
    buf.truncate(packet_payload_start);
    for element in frames {
        match element {
            Element::Crypto(crypto) => {
                crypto.encode(buf);
                stats.frame_tx.crypto += 1;
                sent.retransmits.get_or_create().crypto.push_back(crypto);
            }
            Element::Ping => {
                buf.write(frame::FrameType::PING);
                stats.frame_tx.ping += 1;
                sent.non_retransmits = true;
            }
            Element::Padding(length) => buf.resize(buf.len() + length, 0),
            Element::Preserved { bytes, .. } => buf.extend_from_slice(&bytes),
        }
    }
    sent.requires_padding = true;
    true
}

fn preserve_prefix(prefix: &[u8]) -> Option<Vec<Element>> {
    if prefix.is_empty() {
        return Some(Vec::new());
    }
    let bytes = Bytes::copy_from_slice(prefix);
    let mut iter = frame::Iter::new(bytes.clone()).ok()?;
    let mut start = 0;
    let mut frames = Vec::new();
    while let Some(frame) = iter.next() {
        let frame = frame.ok()?;
        let end = prefix.len() - iter.remaining_bytes();
        frames.push(Element::Preserved {
            bytes: bytes.slice(start..end),
            ack: matches!(frame, Frame::Ack(_)),
        });
        start = end;
    }
    Some(frames)
}

fn crypto_overhead(offset: u64, length: usize) -> usize {
    1 + VarInt::from_u64(offset).unwrap().size() + VarInt::from_u64(length as u64).unwrap().size()
}

fn encoded_size(frames: &[Element]) -> usize {
    frames
        .iter()
        .map(|frame| match frame {
            Element::Crypto(crypto) => {
                crypto_overhead(crypto.offset, crypto.data.len()) + crypto.data.len()
            }
            Element::Ping => 1,
            Element::Padding(length) => *length,
            Element::Preserved { bytes, .. } => bytes.len(),
        })
        .sum()
}

fn take_crypto(
    pending: &mut VecDeque<frame::Crypto>,
    budget: usize,
    packet_payload_size: usize,
    rng: &mut impl Rng,
) -> Vec<Element> {
    let Some(first) = pending.front() else {
        return Vec::new();
    };
    if first.offset == 0 && !first.data.is_empty() {
        let length = first.data.len();
        let overhead = crypto_overhead(length as u64 - 1, length);
        if budget > 2 * overhead && packet_payload_size > overhead {
            let first_capacity = budget - 2 * overhead;
            let other_capacity = packet_payload_size - overhead;
            if length > first_capacity && other_capacity >= first_capacity {
                let occupied = other_capacity - first_capacity;
                let num_packets = (length + occupied).div_ceil(other_capacity);
                let first_length = (length + occupied)
                    .div_ceil(num_packets)
                    .saturating_sub(occupied);
                let prefix_length = 55 + (rng.next_u64() % 32) as usize;
                if first_length > prefix_length {
                    let tail_length = first_length - prefix_length;
                    let tail_offset = length - tail_length;
                    let source = pending.pop_front().unwrap().data;
                    let frames = vec![
                        Element::Crypto(frame::Crypto {
                            offset: 0,
                            data: source.slice(..prefix_length),
                        }),
                        Element::Crypto(frame::Crypto {
                            offset: tail_offset as u64,
                            data: source.slice(tail_offset..),
                        }),
                    ];
                    // The unsent middle remains schedulable even if congestion or
                    // pacing prevents the next packet from being emitted now.
                    pending.push_front(frame::Crypto {
                        offset: prefix_length as u64,
                        data: source.slice(prefix_length..tail_offset),
                    });
                    debug_assert!(encoded_size(&frames) <= budget);
                    return frames;
                }
            }
        }
    }

    let mut frames = Vec::new();
    let mut remaining = budget;
    while let Some(crypto) = pending.front() {
        let overhead = crypto_overhead(crypto.offset, crypto.data.len());
        if remaining <= overhead {
            break;
        }
        let mut crypto = pending.pop_front().unwrap();
        if crypto.data.is_empty() {
            continue;
        }
        let length = crypto.data.len().min(remaining - overhead);
        let fragment = frame::Crypto {
            offset: crypto.offset,
            data: crypto.data.split_to(length),
        };
        remaining -= crypto_overhead(fragment.offset, length) + length;
        frames.push(Element::Crypto(fragment));
        if !crypto.data.is_empty() {
            crypto.offset += length as u64;
            pending.push_front(crypto);
        }
    }
    frames
}

fn protect(frames: &mut Vec<Element>, mut padding: usize, rng: &mut impl Rng) {
    let (start, end) = frames.iter().fold((u64::MAX, 0), |(start, end), frame| {
        let Element::Crypto(crypto) = frame else {
            return (start, end);
        };
        (
            start.min(crypto.offset),
            end.max(crypto.offset + crypto.data.len() as u64),
        )
    });
    let split_overhead = crypto_overhead(end, (end - start) as usize);
    let added_crypto = 2 + rng.next_u64() % 9;
    for _ in 0..added_crypto {
        if padding < split_overhead {
            break;
        }
        let index = (rng.next_u64() % frames.len() as u64) as usize;
        let Element::Crypto(crypto) = &mut frames[index] else {
            continue;
        };
        let old_length = crypto.data.len();
        if old_length <= 1 {
            continue;
        }
        let old_overhead = crypto_overhead(crypto.offset, old_length);
        let length = 1 + (rng.next_u64() % (old_length as u64 - 1)) as usize;
        let new_frame = frame::Crypto {
            offset: crypto.offset + length as u64,
            data: crypto.data.split_off(length),
        };
        let new_overhead = crypto_overhead(crypto.offset, length)
            + crypto_overhead(new_frame.offset, new_frame.data.len());
        padding -= new_overhead - old_overhead;
        frames.push(Element::Crypto(new_frame));
    }

    if padding > 0 {
        let pings = (2 + rng.next_u64() % 9).min(padding as u64) as usize;
        frames.extend((0..pings).map(|_| Element::Ping));
        padding -= pings;
    }

    let mut padded = Vec::with_capacity(frames.len() * 2 + 1);
    for frame in frames.drain(..) {
        let length = (rng.next_u64() % (padding as u64 + 1)) as usize;
        if length > 0 && !matches!(frame, Element::Preserved { ack: true, .. }) {
            padded.push(Element::Padding(length));
            padding -= length;
        }
        padded.push(frame);
    }
    if padding > 0 {
        padded.push(Element::Padding(padding));
    }
    for index in (1..padded.len()).rev() {
        let other = (rng.next_u64() % (index as u64 + 1)) as usize;
        if !matches!(padded[index], Element::Preserved { ack: true, .. })
            && !matches!(padded[other], Element::Preserved { ack: true, .. })
        {
            padded.swap(index, other);
        }
    }
    *frames = padded;
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;
    use crate::Frame;

    #[test]
    fn initial_chaos_covers_variable_crypto_exactly_with_bounded_packets() {
        for length in [
            1, 54, 55, 63, 64, 86, 255, 1100, 1185, 1190, 1700, 2048, 4096, 16384, 65536,
        ] {
            for budget in [96, 1139, 1200, 1300] {
                for seed in 0..16 {
                    let source =
                        Bytes::from((0..length).map(|index| index as u8).collect::<Vec<_>>());
                    let mut pending = VecDeque::from([frame::Crypto {
                        offset: 0,
                        data: source.clone(),
                    }]);
                    let mut rng = StdRng::seed_from_u64(seed);
                    let mut coverage = vec![0u8; length];
                    while !pending.is_empty() {
                        let mut sent = SentFrames::default();
                        let mut buf = Vec::new();
                        assert!(populate_packet(
                            &mut pending,
                            &mut buf,
                            budget,
                            0,
                            &mut rng,
                            &mut sent,
                            &mut ConnectionStats::default()
                        ));
                        assert_eq!(buf.len(), budget);
                        let mut decoded = Vec::new();
                        for frame in frame::Iter::new(buf.into()).unwrap() {
                            if let Frame::Crypto(crypto) = frame.unwrap() {
                                let start = crypto.offset as usize;
                                let end = start + crypto.data.len();
                                assert_eq!(crypto.data, source.slice(start..end));
                                for count in &mut coverage[start..end] {
                                    *count += 1;
                                }
                                decoded.push((crypto.offset, crypto.data));
                            }
                        }
                        let tracked: Vec<_> = sent
                            .retransmits
                            .get_or_create()
                            .crypto
                            .iter()
                            .map(|crypto| (crypto.offset, crypto.data.clone()))
                            .collect();
                        assert_eq!(decoded, tracked);
                    }
                    assert!(
                        coverage.iter().all(|&count| count == 1),
                        "length={length} budget={budget} seed={seed}"
                    );
                }
            }
        }
    }

    #[test]
    fn initial_chaos_first_packet_contains_prefix_and_tail() {
        let length = 2000;
        let mut pending = VecDeque::from([frame::Crypto {
            offset: 0,
            data: Bytes::from(vec![42; length]),
        }]);
        let mut rng = StdRng::seed_from_u64(153);
        let frames = take_crypto(&mut pending, 1200, 1200, &mut rng);
        let Element::Crypto(prefix) = &frames[0] else {
            panic!()
        };
        let Element::Crypto(tail) = &frames[1] else {
            panic!()
        };
        assert!((55..87).contains(&prefix.data.len()));
        assert_eq!(prefix.offset, 0);
        assert_eq!(tail.offset as usize + tail.data.len(), length);
        assert_eq!(prefix.data.len() + tail.data.len(), 998);
        assert_eq!(pending[0].offset, prefix.data.len() as u64);
        assert_eq!(
            pending[0].offset + pending[0].data.len() as u64,
            tail.offset
        );
    }

    #[test]
    fn initial_chaos_insufficient_budget_preserves_pending_data() {
        let source = Bytes::from_static(b"client hello");
        let mut pending = VecDeque::from([frame::Crypto {
            offset: 0,
            data: source.clone(),
        }]);
        let mut rng = StdRng::seed_from_u64(153);
        let mut buf = vec![9; 100];
        assert!(!populate_packet(
            &mut pending,
            &mut buf,
            102,
            100,
            &mut rng,
            &mut SentFrames::default(),
            &mut ConnectionStats::default()
        ));
        assert_eq!(buf, vec![9; 100]);
        assert_eq!(pending[0].data, source);
    }

    #[test]
    fn initial_chaos_nearly_full_first_packet_falls_back_without_underflow() {
        let mut pending = VecDeque::from([frame::Crypto {
            offset: 0,
            data: Bytes::from(vec![42; 2000]),
        }]);
        let mut rng = StdRng::seed_from_u64(153);
        let frames = take_crypto(&mut pending, 100, 1200, &mut rng);
        assert_eq!(frames.len(), 1);
        assert!(encoded_size(&frames) <= 100);
        assert_eq!(pending[0].offset, 96);
    }

    #[test]
    fn initial_chaos_preserves_ack_bytes_position_and_existing_ping_statistics() {
        use crate::range_set::ArrayRangeSet;

        let mut ranges = ArrayRangeSet::new();
        ranges.insert(1..5);
        ranges.insert(8..10);
        let mut ack = Vec::new();
        frame::Ack::encode(3, &ranges, Some(&frame::EcnCounts::ZERO), &mut ack);
        for seed in 0..16 {
            let mut buf = vec![0xaa; 34];
            buf.extend_from_slice(&ack);
            buf.write(frame::FrameType::PING);
            let mut pending = VecDeque::from([frame::Crypto {
                offset: 0,
                data: Bytes::from(vec![42; 100]),
            }]);
            let mut stats = ConnectionStats::default();
            stats.frame_tx.acks = 1;
            stats.frame_tx.ping = 1;
            assert!(populate_packet(
                &mut pending,
                &mut buf,
                234,
                34,
                &mut StdRng::seed_from_u64(seed),
                &mut SentFrames::default(),
                &mut stats,
            ));
            assert_eq!(buf.len(), 234);
            assert_eq!(&buf[..34], &[0xaa; 34]);
            assert_eq!(&buf[34..34 + ack.len()], ack.as_slice());
            let decoded_pings = frame::Iter::new(Bytes::copy_from_slice(&buf[34..]))
                .unwrap()
                .filter(|frame| matches!(frame, Ok(Frame::Ping)))
                .count();
            assert_eq!(decoded_pings as u64, stats.frame_tx.ping);
            assert_eq!(stats.frame_tx.acks, 1);
        }
    }

    #[test]
    fn initial_chaos_matches_chromium_zero_random_sequence() {
        struct ZeroRandom;
        impl rand::TryRng for ZeroRandom {
            type Error = std::convert::Infallible;

            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Ok(0)
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Ok(0)
            }
            fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
                bytes.fill(0);
                Ok(())
            }
        }
        let mut frames = vec![Element::Crypto(frame::Crypto {
            offset: 0,
            data: Bytes::from(vec![42; 100]),
        })];
        protect(&mut frames, 96, &mut ZeroRandom);
        assert_eq!(encoded_size(&frames), 200);
        // Chromium's four passes with all random values zero leave the
        // offset-zero byte last, two PINGs, and one 91-byte padding run.
        assert!(
            matches!(&frames[0], Element::Crypto(crypto) if crypto.offset == 1 && crypto.data.len() == 99)
        );
        assert!(matches!(&frames[1], Element::Ping));
        assert!(matches!(&frames[2], Element::Ping));
        assert!(matches!(&frames[3], Element::Padding(91)));
        assert!(
            matches!(&frames[4], Element::Crypto(crypto) if crypto.offset == 0 && crypto.data.len() == 1)
        );
    }
}
