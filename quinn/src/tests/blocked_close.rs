use super::*;

async fn case(discard: bool) -> RuntimeCase {
    let clock = Clock::new();
    let ((client_ep, server_ep, client_socket, server_socket), _) =
        configured_endpoints_with_close_policy(clock.clone(), true, false, false, discard);
    let (client, server) = with_clock(&clock, async {
        join!(
            client_ep
                .connect(server_ep.local_addr().unwrap(), "localhost")
                .unwrap(),
            async { server_ep.accept().await.unwrap().await }
        )
    })
    .await;
    let client = client.unwrap();
    let server = server.unwrap();
    clock.advance(Duration::from_millis(50));
    until(|| client.stats().frame_rx.handshake_done > 0).await;
    settle().await;
    RuntimeCase {
        clock,
        client_ep,
        server_ep,
        client,
        server,
        client_socket,
        server_socket,
    }
}

fn sent(socket: &GateSocket) -> usize {
    socket
        .state
        .lock()
        .unwrap()
        .attempts
        .iter()
        .filter(|attempt| attempt.sent)
        .count()
}

async fn cleanup(case: RuntimeCase) {
    {
        let mut gate = case.client_socket.state.lock().unwrap();
        gate.send_error = None;
        gate.poll_error = None;
    }
    case.client_socket.release();
    case.server_socket.release();
    case.client_ep.close(0u32.into(), b"test cleanup");
    case.server_ep.close(0u32.into(), b"test cleanup");
    settle().await;
    case.clock.advance(Duration::from_secs(60));
    with_clock(&case.clock, async {
        join!(case.client_ep.wait_idle(), case.server_ep.wait_idle());
    })
    .await;
    let RuntimeCase {
        clock,
        client_ep,
        server_ep,
        client,
        server,
        client_socket,
        server_socket,
    } = case;
    drop((client, server, client_ep, server_ep));
    until(|| clock.tasks.load(Ordering::SeqCst) == 0).await;
    assert_eq!(client_socket.live_pollers(), 0);
    assert_eq!(server_socket.live_pollers(), 0);
    assert_eq!(
        clock
            .state
            .lock()
            .unwrap()
            .timers
            .iter()
            .filter(|timer| timer.strong_count() > 0)
            .count(),
        0
    );
}

async fn verify_after_release(case: &RuntimeCase, discard: bool, sent_before: usize) {
    case.client_socket.release();
    if discard {
        settle().await;
        assert_eq!(
            sent(&case.client_socket),
            sent_before,
            "discarded Close must not resume when writable"
        );
        assert!(case.server.close_reason().is_none());
        // Exercise a real incoming datagram, not just an elapsed quiet interval.
        let received = case.client.stats().udp_rx.datagrams;
        case.server
            .send_datagram(Bytes::from_static(b"post-close probe"))
            .unwrap();
        until(|| case.client.stats().udp_rx.datagrams > received).await;
        settle().await;
        assert_eq!(
            sent(&case.client_socket),
            sent_before,
            "incoming packets must not revive a suppressed Close"
        );
        assert!(case.server.close_reason().is_none());
    } else {
        let reason = timeout(Duration::from_secs(3), case.server.closed())
            .await
            .unwrap();
        assert!(
            matches!(reason, crate::ConnectionError::ApplicationClosed(close) if close.error_code.into_inner() == 259)
        );
        assert!(sent(&case.client_socket) > sent_before);
    }
}

#[tokio::test]
async fn blocked_close_writable_path_still_sends_application_close() {
    for discard in [false, true] {
        let case = case(discard).await;
        let sent_before = sent(&case.client_socket);
        case.client.close(259u32.into(), b"writable control");
        let reason = timeout(Duration::from_secs(3), case.server.closed())
            .await
            .unwrap();
        assert!(
            matches!(reason, crate::ConnectionError::ApplicationClosed(close) if close.error_code.into_inner() == 259)
        );
        assert!(sent(&case.client_socket) > sent_before);
        assert_eq!(case.client_socket.blocked_attempts(), 0);
        cleanup(case).await;
    }
}

#[tokio::test]
async fn blocked_close_try_send_wouldblock_obeys_profile_policy() {
    for discard in [false, true] {
        let case = case(discard).await;
        let sent_before = sent(&case.client_socket);
        case.client_socket.arm();
        case.client.close(259u32.into(), b"send WouldBlock control");
        until(|| case.client_socket.blocked_attempts() > 0).await;
        assert_eq!(case.client_socket.blocked_attempts(), 1);
        let bytes = case
            .client_socket
            .state
            .lock()
            .unwrap()
            .attempts
            .iter()
            .find(|attempt| attempt.blocked)
            .unwrap()
            .ciphertext
            .clone();
        assert_eq!(bytes[0] & 0x80, 0);
        assert!(matches!(
            case.client.close_reason(),
            Some(crate::ConnectionError::LocallyClosed)
        ));
        verify_after_release(&case, discard, sent_before).await;
        assert_eq!(case.client_socket.resent(&bytes), !discard);
        cleanup(case).await;
    }
}

#[tokio::test]
async fn blocked_close_pending_poller_obeys_profile_policy() {
    for discard in [false, true] {
        let case = case(discard).await;
        let sent_before = sent(&case.client_socket);
        case.client_socket.state.lock().unwrap().blocked = true;
        case.client.close(259u32.into(), b"poll Pending control");
        until(|| case.client_socket.state.lock().unwrap().pending_polls > 0).await;
        assert!(case.client_socket.state.lock().unwrap().pending_polls > 0);
        assert_eq!(
            case.client_socket.blocked_attempts(),
            0,
            "poll Pending must precede any send attempt"
        );
        assert!(matches!(
            case.client.close_reason(),
            Some(crate::ConnectionError::LocallyClosed)
        ));
        verify_after_release(&case, discard, sent_before).await;
        cleanup(case).await;
    }
}

#[tokio::test]
async fn blocked_close_old_application_packet_is_discarded_in_both_modes() {
    for discard in [false, true] {
        let case = case(discard).await;
        let (upload, request, bytes) = case.blocked_tail().await;
        let sent_before = sent(&case.client_socket);
        let pending_before = case.client_socket.state.lock().unwrap().pending_polls;
        let attempts_before = case.client_socket.state.lock().unwrap().attempts.len();
        case.client
            .close(259u32.into(), b"old application buffer control");
        if discard {
            settle().await;
            assert!(matches!(
                case.client.close_reason(),
                Some(crate::ConnectionError::LocallyClosed)
            ));
            let gate = case.client_socket.state.lock().unwrap();
            assert_eq!(
                gate.pending_polls, pending_before,
                "known blocked writer suppresses the fresh Close before polling"
            );
            assert_eq!(gate.attempts.len(), attempts_before);
        } else {
            until(|| case.client_socket.state.lock().unwrap().pending_polls > pending_before).await;
        }
        verify_after_release(&case, discard, sent_before).await;
        assert!(
            !case.client_socket.resent(&bytes),
            "old application ciphertext cannot become the closing packet"
        );
        drop((upload, request));
        cleanup(case).await;
    }
}

#[tokio::test]
async fn blocked_close_hard_io_errors_drain_without_waiting_for_close_timer() {
    for discard in [false, true] {
        for fail_poll in [false, true] {
            let case = case(discard).await;
            let sent_before = sent(&case.client_socket);
            {
                let mut gate = case.client_socket.state.lock().unwrap();
                if fail_poll {
                    gate.poll_error = Some(io::ErrorKind::PermissionDenied);
                } else {
                    gate.send_error = Some(io::ErrorKind::PermissionDenied);
                }
            }
            case.client.close(259u32.into(), b"hard I/O control");
            until(|| case.client_socket.state.lock().unwrap().injected_errors > 0).await;
            assert_eq!(case.client_socket.state.lock().unwrap().injected_errors, 1);
            timeout(Duration::from_secs(1), case.client_ep.wait_idle())
                .await
                .expect("hard I/O must drain without advancing the frozen protocol clock");
            assert_eq!(sent(&case.client_socket), sent_before);
            assert!(
                matches!(
                    case.client.close_reason(),
                    Some(crate::ConnectionError::LocallyClosed)
                ),
                "a late I/O error must retain the already-published local close cause"
            );
            assert!(case.server.close_reason().is_none());
            cleanup(case).await;
        }
    }
}
