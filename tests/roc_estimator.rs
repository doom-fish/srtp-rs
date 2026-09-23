//! Unit tests for the receiver ROC estimator (RFC 3711 Appendix A).

use srtp::roc::{ReceiverRoc, SenderRoc};

#[test]
fn sender_roc_increments_on_wrap() {
    let mut tx = SenderRoc::new();
    assert_eq!(tx.next(0xfffe).unwrap(), 0);
    assert_eq!(tx.next(0xffff).unwrap(), 0);
    assert_eq!(tx.next(0x0000).unwrap(), 1); // wrapped
    assert_eq!(tx.next(0x0001).unwrap(), 1);
    assert_eq!(tx.roc(), 1);
}

#[test]
fn sender_roc_no_wrap_on_small_step() {
    let mut tx = SenderRoc::new();
    assert_eq!(tx.next(10).unwrap(), 0);
    assert_eq!(tx.next(11).unwrap(), 0);
    assert_eq!(tx.next(9).unwrap(), 0); // small reorder, not a wrap
    assert_eq!(tx.roc(), 0);
}

#[test]
fn receiver_estimates_first_packet() {
    let rx = ReceiverRoc::new();
    let (roc, index) = rx.estimate(0x1234).unwrap();
    assert_eq!(roc, 0);
    assert_eq!(index, 0x1234);
}

#[test]
fn receiver_tracks_forward_wrap() {
    let mut rx = ReceiverRoc::new();
    for seq in [0xfffd_u16, 0xfffe, 0xffff] {
        let (roc, _) = rx.estimate(seq).unwrap();
        rx.update(seq, roc);
    }
    assert_eq!(rx.roc(), 0);

    // Packet after the wrap: estimator must guess ROC = 1.
    let (roc, index) = rx.estimate(0x0000).unwrap();
    assert_eq!(roc, 1);
    assert_eq!(index, 1 << 16);
    rx.update(0x0000, roc);
    assert_eq!(rx.roc(), 1);
    assert_eq!(rx.highest_seq(), Some(0));
}

#[test]
fn receiver_handles_late_packet_from_before_wrap() {
    let mut rx = ReceiverRoc::new();
    for seq in [0xfffe_u16, 0xffff, 0x0000, 0x0001] {
        let (roc, _) = rx.estimate(seq).unwrap();
        rx.update(seq, roc);
    }
    assert_eq!(rx.roc(), 1);

    // A straggler from just before the wrap should map back to ROC 0.
    let (roc, index) = rx.estimate(0xfffd).unwrap();
    assert_eq!(roc, 0);
    assert_eq!(index, 0xfffd);
}

#[test]
fn sender_and_receiver_agree_when_the_sender_reorders_across_a_wrap() {
    let mut tx = SenderRoc::new();
    let mut rx = ReceiverRoc::new();
    for (seq, expected_roc) in [
        (0xffff_u16, 0),
        (0x0000, 1),
        (0xfffe, 0),
        (0x0001, 1),
        (0x0002, 1),
    ] {
        let sent_roc = tx.next(seq).unwrap();
        let (guessed_roc, _) = rx.estimate(seq).unwrap();
        rx.update(seq, guessed_roc);
        assert_eq!(sent_roc, expected_roc);
        assert_eq!(guessed_roc, expected_roc);
    }
    assert_eq!(tx.roc(), 1);
}

#[test]
fn sender_refuses_to_reuse_an_index() {
    let mut tx = SenderRoc::new();
    assert_eq!(tx.next(5).unwrap(), 0);
    assert!(matches!(tx.next(5), Err(srtp::SrtpError::IndexReused)));
    assert_eq!(tx.next(4).unwrap(), 0);
    assert!(matches!(tx.next(4), Err(srtp::SrtpError::IndexReused)));
    assert_eq!(tx.next(6).unwrap(), 0);
}

#[test]
fn receiver_never_guesses_a_rollover_counter_below_zero() {
    let mut rx = ReceiverRoc::new();
    rx.update(100, 0);
    assert_eq!(rx.estimate(0xff00).unwrap(), (0, 0xff00));
}

#[test]
fn rollover_counter_never_wraps_past_its_last_value() {
    let mut tx = SenderRoc::with_roc(u32::MAX);
    assert_eq!(tx.next(0xfffe).unwrap(), u32::MAX);
    assert_eq!(tx.next(0xffff).unwrap(), u32::MAX);
    assert!(matches!(tx.next(0x0000), Err(srtp::SrtpError::KeyExpired)));
    assert_eq!(tx.roc(), u32::MAX);

    let mut rx = ReceiverRoc::with_roc(u32::MAX);
    let (roc, index) = rx.estimate(0xffff).unwrap();
    assert_eq!(index, (1 << 48) - 1);
    rx.update(0xffff, roc);
    assert!(matches!(
        rx.estimate(0x0000),
        Err(srtp::SrtpError::KeyExpired)
    ));
}
