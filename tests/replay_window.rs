//! Unit tests for the sliding anti-replay window (RFC 3711 §3.3.2).

use srtp::replay::{ReplayCheck, ReplayWindow, WINDOW_SIZE};

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
    w.mark(1000);
    let too_old = 1000 - WINDOW_SIZE;
    assert_eq!(w.check(too_old), ReplayCheck::Replayed);
    // Just inside the trailing edge is still acceptable.
    assert_eq!(w.check(1000 - (WINDOW_SIZE - 1)), ReplayCheck::Ok);
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
