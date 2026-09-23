//! Unit tests for the sliding anti-replay window (RFC 3711 §3.3.2).

use srtp::replay::{
    ReplayCheck, ReplayWindow, DEFAULT_WINDOW_SIZE, MAX_WINDOW_SIZE, MIN_WINDOW_SIZE,
};
use srtp::rtp::{Packet, RtpPacket};
use srtp::{Profile, SrtpError, SrtpKey, SrtpSession};

const WINDOW_SIZE: u64 = DEFAULT_WINDOW_SIZE as u64;

#[test]
fn first_packet_is_accepted() {
    let mut w = ReplayWindow::new();
    assert_eq!(w.check(42), ReplayCheck::Ok);
    w.mark(42);
}

#[test]
fn exact_replay_is_rejected() {
    let mut w = ReplayWindow::new();
    w.mark(10);
    assert_eq!(w.check(10), ReplayCheck::Replayed);
}

#[test]
fn forward_progress_is_accepted() {
    let mut w = ReplayWindow::new();
    w.mark(10);
    assert_eq!(w.check(11), ReplayCheck::Ok);
    w.mark(11);
    assert_eq!(w.check(100), ReplayCheck::Ok);
    w.mark(100);
}

#[test]
fn in_window_reorder_is_accepted_once() {
    let mut w = ReplayWindow::new();
    w.mark(100);
    // An older but in-window index that hasn't been seen is fine.
    assert_eq!(w.check(80), ReplayCheck::Ok);
    w.mark(80);
    // But not a second time.
    assert_eq!(w.check(80), ReplayCheck::Replayed);
}

#[test]
fn too_old_is_rejected() {
    let mut w = ReplayWindow::new();
    w.mark(5000);
    let too_old = 5000 - WINDOW_SIZE;
    assert_eq!(w.check(too_old), ReplayCheck::Replayed);
    // Just inside the trailing edge is still acceptable.
    assert_eq!(w.check(5000 - (WINDOW_SIZE - 1)), ReplayCheck::Ok);
}

#[test]
fn large_jump_clears_stale_bits() {
    let mut w = ReplayWindow::new();
    w.mark(5);
    w.mark(6);
    // Jump far ahead; the old indices fall out of the window.
    w.mark(5 + WINDOW_SIZE + 10);
    assert_eq!(w.check(5), ReplayCheck::Replayed);
    assert_eq!(w.check(6), ReplayCheck::Replayed);
}

#[test]
fn window_size_is_configurable_from_64_to_1024() {
    assert_eq!(DEFAULT_WINDOW_SIZE, 1024);
    assert_eq!(ReplayWindow::new().size(), DEFAULT_WINDOW_SIZE);
    assert_eq!(ReplayWindow::with_size(MIN_WINDOW_SIZE).unwrap().size(), 64);
    assert_eq!(
        ReplayWindow::with_size(MAX_WINDOW_SIZE).unwrap().size(),
        1024
    );
    assert!(matches!(
        ReplayWindow::with_size(MIN_WINDOW_SIZE - 1),
        Err(SrtpError::InvalidReplayWindow(63))
    ));
    assert!(matches!(
        ReplayWindow::with_size(MAX_WINDOW_SIZE + 1),
        Err(SrtpError::InvalidReplayWindow(1025))
    ));
}

#[test]
fn trailing_edge_follows_the_configured_size() {
    let mut small = ReplayWindow::with_size(64).unwrap();
    let mut large = ReplayWindow::new();
    small.mark(2000);
    large.mark(2000);
    assert_eq!(small.check(2000 - 64), ReplayCheck::Replayed);
    assert_eq!(small.check(2000 - 63), ReplayCheck::Ok);
    assert_eq!(large.check(2000 - 64), ReplayCheck::Ok);
    assert_eq!(large.check(2000 - 1023), ReplayCheck::Ok);
    assert_eq!(large.check(2000 - 1024), ReplayCheck::Replayed);
}

#[test]
fn reused_bitmap_positions_forget_indices_that_left_the_window() {
    let mut w = ReplayWindow::new();
    w.mark(5);
    w.mark(6);
    w.mark(5 + WINDOW_SIZE - 1);
    assert_eq!(w.check(5), ReplayCheck::Replayed);
    assert_eq!(w.check(6), ReplayCheck::Replayed);
    assert_eq!(w.check(7), ReplayCheck::Ok);

    w.mark(5 + WINDOW_SIZE);
    w.mark(7 + WINDOW_SIZE);
    assert_eq!(w.check(6 + WINDOW_SIZE), ReplayCheck::Ok);
    assert_eq!(w.check(7 + WINDOW_SIZE), ReplayCheck::Replayed);
    assert_eq!(w.check(6), ReplayCheck::Replayed);
}

#[test]
fn video_burst_reordered_beyond_64_packets_is_accepted_by_default() {
    let key = SrtpKey::from_master(&[7u8; 16], &[9u8; 12], Profile::AeadAes128Gcm).unwrap();
    let mut tx = SrtpSession::new_sender(key.clone());
    let mut rx = SrtpSession::new_receiver(key.clone());
    let mut rx_small = SrtpSession::new_receiver(key)
        .with_replay_window(64)
        .unwrap();

    let mut protected = Vec::new();
    for seq in 0u16..400 {
        let packet = RtpPacket::builder()
            .ssrc(0x5eed_0001)
            .sequence_number(seq)
            .payload(seq.to_be_bytes())
            .build()
            .unwrap();
        let mut out = vec![0u8; 64];
        let n = tx.protect(&packet.as_view(), &mut out).unwrap();
        out.truncate(n);
        protected.push(out);
    }

    let mut late = protected.remove(100);
    for packet in &protected {
        rx.unprotect(&mut packet.clone()).unwrap();
        rx_small.unprotect(&mut packet.clone()).unwrap();
    }
    assert_eq!(
        rx.unprotect(&mut late.clone()).unwrap().payload(),
        100u16.to_be_bytes()
    );
    assert!(matches!(
        rx_small.unprotect(&mut late.clone()),
        Err(SrtpError::Replay)
    ));
    assert!(matches!(rx.unprotect(&mut late), Err(SrtpError::Replay)));
}
