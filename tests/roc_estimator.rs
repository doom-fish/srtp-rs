//! Unit tests for the receiver ROC estimator (RFC 3711 Appendix A).

use srtp::roc::{ReceiverRoc, SenderRoc};

#[test]
fn sender_roc_increments_on_wrap() {
    let mut tx = SenderRoc::new();
    assert_eq!(tx.next(0xfffe), 0);
    assert_eq!(tx.next(0xffff), 0);
    assert_eq!(tx.next(0x0000), 1); // wrapped
    assert_eq!(tx.next(0x0001), 1);
    assert_eq!(tx.roc(), 1);
}

#[test]
fn sender_roc_no_wrap_on_small_step() {
    let mut tx = SenderRoc::new();
    assert_eq!(tx.next(10), 0);
    assert_eq!(tx.next(11), 0);
    assert_eq!(tx.next(9), 0); // small reorder, not a wrap
    assert_eq!(tx.roc(), 0);
}

#[test]
fn receiver_estimates_first_packet() {
    let rx = ReceiverRoc::new();
    let (roc, index) = rx.estimate(0x1234);
    assert_eq!(roc, 0);
    assert_eq!(index, 0x1234);
}

#[test]
fn receiver_tracks_forward_wrap() {
    let mut rx = ReceiverRoc::new();
    for seq in [0xfffd_u16, 0xfffe, 0xffff] {
        let (roc, _) = rx.estimate(seq);
        rx.update(seq, roc);
    }
    assert_eq!(rx.roc(), 0);

    // Packet after the wrap: estimator must guess ROC = 1.
    let (roc, index) = rx.estimate(0x0000);
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
        let (roc, _) = rx.estimate(seq);
        rx.update(seq, roc);
    }
    assert_eq!(rx.roc(), 1);

    // A straggler from just before the wrap should map back to ROC 0.
    let (roc, index) = rx.estimate(0xfffd);
    assert_eq!(roc, 0);
    assert_eq!(index, 0xfffd);
}
