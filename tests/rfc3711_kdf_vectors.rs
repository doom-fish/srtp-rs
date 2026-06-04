//! RFC 3711 §B.3 key-derivation-function test vectors.

mod common;
use common::{hex, to_hex};

use srtp::kdf;

#[test]
fn kdf_cipher_key_salt_auth_b3() {
    let master_key = hex("E1F97A0D3E018BE0D64FA32C06DE4139");
    let master_salt = hex("0EC675AD498AFEEBB6960B3AABE6");

    let cipher_key =
        kdf::derive(&master_key, &master_salt, kdf::LABEL_SRTP_ENCRYPTION, 16).unwrap();
    assert_eq!(to_hex(&cipher_key), "c61e7a93744f39ee10734afe3ff7a087");

    let cipher_salt = kdf::derive(&master_key, &master_salt, kdf::LABEL_SRTP_SALT, 14).unwrap();
    assert_eq!(to_hex(&cipher_salt), "30cbbc08863d8c85d49db34a9ae1");

    let auth_key = kdf::derive(&master_key, &master_salt, kdf::LABEL_SRTP_AUTH, 94).unwrap();
    let expected_auth = hex(
        "CEBE321F6FF7716B6FD4AB49AF256A15 \
         6D38BAA48F0A0ACF3C34E2359E6CDBCE \
         E049646C43D9327AD175578EF7227098 \
         6371C10C9A369AC2F94A8C5FBCDDDC25 \
         6D6E919A48B610EF17C2041E47403576 \
         6B68642C59BBFC2F34DB60DBDFB2",
    );
    assert_eq!(to_hex(&auth_key), to_hex(&expected_auth));
    assert_eq!(auth_key.len(), 94);
}
