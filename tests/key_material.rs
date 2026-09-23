use srtp::{Profile, SessionKeys, SrtcpSession, SrtpKey, SrtpSession};

#[test]
fn debug_output_never_contains_key_material() {
    let derived =
        SrtpKey::from_master(&[0xab; 16], &[0xcd; 14], Profile::AesCm128HmacSha1_80).unwrap();
    let injected = SrtpKey::from_session(
        Profile::AeadAes128Gcm,
        SessionKeys {
            encryption: &[0x11; 16],
            salt: &[0x22; 12],
            authentication: &[],
        },
        SessionKeys {
            encryption: &[0x33; 16],
            salt: &[0x44; 12],
            authentication: &[],
        },
    )
    .unwrap();

    assert_eq!(
        format!("{derived:?}"),
        "SrtpKey { profile: AesCm128HmacSha1_80, .. }"
    );
    assert_eq!(
        format!("{injected:?}"),
        "SrtpKey { profile: AeadAes128Gcm, .. }"
    );
    assert_eq!(format!("{injected:#?}").matches("17").count(), 0);

    let media = format!("{:?}", SrtpSession::new_sender(injected.clone()));
    let control = format!("{:?}", SrtcpSession::new_receiver(injected));
    for text in [media, control] {
        assert!(
            text.contains("key: SrtpKey { profile: AeadAes128Gcm, .. }"),
            "{text}"
        );
    }
}
