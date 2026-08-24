/*
 * Copyright (C) 2026 David Byers dba Byers Brands
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

use did_rust::crypto::{
    derive_ed25519_did, derive_identity_from_prf, derive_nostr_keypair, CryptoError,
    DerivedIdentity,
};
use did_rust::vault_crypto::{decrypt_vault_payload, encrypt_vault_payload, HEADER_LEN};
use did_rust::{
    decrypt_vault_payload_ffi, derive_identity_from_prf_ffi, encrypt_vault_payload_ffi, free_string,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};

const TEST_SEED: [u8; 32] = [
    0x5a, 0xf2, 0x11, 0x9c, 0xe3, 0x40, 0xab, 0x71, 0xd8, 0x02, 0x66, 0x1b, 0xfa, 0x93, 0x55, 0xc4,
    0x7e, 0x10, 0x83, 0x2d, 0xb9, 0x64, 0xef, 0x07, 0x3c, 0xa1, 0x58, 0xcc, 0x20, 0xfd, 0x91, 0x36,
];

#[test]
fn test_deterministic_parity_across_runs() {
    let run_a: DerivedIdentity = derive_identity_from_prf(&TEST_SEED, 42).unwrap();
    let run_b: DerivedIdentity = derive_identity_from_prf(&TEST_SEED, 42).unwrap();

    assert_eq!(run_a.did, run_b.did);
    assert_eq!(run_a.nostr_pubkey_hex, run_b.nostr_pubkey_hex);
    assert_eq!(run_a.ed25519_priv_bytes, run_b.ed25519_priv_bytes);
    assert_eq!(run_a.secp256k1_priv_bytes, run_b.secp256k1_priv_bytes);

    let (did_direct, ed_priv_direct) = derive_ed25519_did(&TEST_SEED, 42).unwrap();
    let (nostr_hex_direct, secp_priv_direct) = derive_nostr_keypair(&TEST_SEED, 42).unwrap();
    assert_eq!(did_direct, run_a.did);
    assert_eq!(ed_priv_direct, run_a.ed25519_priv_bytes);
    assert_eq!(nostr_hex_direct, run_a.nostr_pubkey_hex);
    assert_eq!(secp_priv_direct, run_a.secp256k1_priv_bytes);
}

#[test]
fn test_index_and_seed_sensitivity() {
    let idx0 = derive_identity_from_prf(&TEST_SEED, 0).unwrap();
    let idx1 = derive_identity_from_prf(&TEST_SEED, 1).unwrap();

    assert_ne!(idx0.did, idx1.did);
    assert_ne!(idx0.nostr_pubkey_hex, idx1.nostr_pubkey_hex);
    assert_ne!(idx0.ed25519_priv_bytes, idx1.ed25519_priv_bytes);
    assert_ne!(idx0.secp256k1_priv_bytes, idx1.secp256k1_priv_bytes);

    let mut other_seed = TEST_SEED;
    other_seed[0] ^= 0x01;
    let other = derive_identity_from_prf(&other_seed, 0).unwrap();
    assert_ne!(idx0.did, other.did);
    assert_ne!(idx0.nostr_pubkey_hex, other.nostr_pubkey_hex);
}

#[test]
fn test_did_key_format_is_canonical_ed25519() {
    let identity = derive_identity_from_prf(&TEST_SEED, 0).unwrap();
    assert!(identity.did.starts_with("did:key:z6Mk"));

    let body = identity.did.strip_prefix("did:key:z").unwrap();
    let decoded = bs58::decode(body).into_vec().unwrap();
    assert_eq!(decoded.len(), 34);
    assert_eq!(&decoded[..2], &[0xed, 0x01]);

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&identity.ed25519_priv_bytes);
    assert_eq!(
        &decoded[2..],
        signing_key.verifying_key().as_bytes().as_slice()
    );
}

#[test]
fn test_nostr_pubkey_format_is_xonly_hex() {
    let identity = derive_identity_from_prf(&TEST_SEED, 0).unwrap();
    assert_eq!(identity.nostr_pubkey_hex.len(), 64);
    assert!(identity
        .nostr_pubkey_hex
        .chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));

    let secret =
        k256::SecretKey::from_bytes(k256::FieldBytes::from_slice(&identity.secp256k1_priv_bytes))
            .unwrap();
    let encoded = secret.public_key().to_encoded_point(false);
    let x_only = &encoded.as_ref()[1..33];
    assert_eq!(hex::encode(x_only), identity.nostr_pubkey_hex);
}

#[test]
fn test_curve_separation_via_domain_split_hashes() {
    let index: u32 = 5;
    let index_le = index.to_le_bytes();

    let ed_hash: [u8; 32] = Sha256::digest([TEST_SEED.as_slice(), &index_le].concat()).into();
    let nostr_hash: [u8; 32] = Sha256::digest(
        [
            b"secp256k1-nostr".as_slice(),
            TEST_SEED.as_slice(),
            &index_le,
        ]
        .concat(),
    )
    .into();

    assert_ne!(ed_hash, nostr_hash);

    let (_, ed_priv) = derive_ed25519_did(&TEST_SEED, index).unwrap();
    let (_, secp_priv) = derive_nostr_keypair(&TEST_SEED, index).unwrap();

    assert_eq!(ed_priv, ed_hash);
    assert_eq!(secp_priv, nostr_hash);
    assert_ne!(ed_priv, secp_priv);

    let identity = derive_identity_from_prf(&TEST_SEED, index).unwrap();
    assert_ne!(identity.ed25519_priv_bytes, identity.secp256k1_priv_bytes);
    assert_ne!(
        hex::encode(identity.ed25519_priv_bytes),
        identity.nostr_pubkey_hex
    );
}

#[test]
fn test_scalar_retry_stays_deterministic() {
    for seed_byte in [0x00u8, 0x01, 0xFF] {
        let seed = [seed_byte; 32];
        let a = derive_nostr_keypair(&seed, u32::MAX).unwrap();
        let b = derive_nostr_keypair(&seed, u32::MAX).unwrap();
        assert_eq!(a.0, b.0);
        assert_eq!(a.1, b.1);
        assert_eq!(a.1.len(), 32);
        assert!(a.1.iter().any(|&b| b != 0));
    }
}

#[test]
fn test_vault_roundtrip_encryption() {
    let kek: [u8; 32] = Sha256::digest(b"prf-derived-kek-material").into();
    let vault_json = r#"{
        "version": 1,
        "entries": [
            {"id": "cred-1", "type": "VerifiableCredential"},
            {"id": "cred-2", "type": "NostrNsec"}
        ]
    }"#;

    let sealed = encrypt_vault_payload(&kek, vault_json.as_bytes()).unwrap();
    assert_eq!(sealed.len(), vault_json.len() + HEADER_LEN);

    let opened = decrypt_vault_payload(&kek, &sealed).unwrap();
    assert_eq!(opened, vault_json.as_bytes());

    let empty = encrypt_vault_payload(&kek, b"").unwrap();
    assert_eq!(empty.len(), HEADER_LEN);
    assert!(decrypt_vault_payload(&kek, &empty).unwrap().is_empty());
}

#[test]
fn test_vault_nonce_uniqueness() {
    let kek = [0x33u8; 32];
    let plaintext = b"same payload";
    let sealed_a = encrypt_vault_payload(&kek, plaintext).unwrap();
    let sealed_b = encrypt_vault_payload(&kek, plaintext).unwrap();
    assert_ne!(sealed_a, sealed_b);
    assert_ne!(&sealed_a[..12], &sealed_b[..12]);
    assert!(decrypt_vault_payload(&kek, &sealed_a)
        .unwrap()
        .eq(plaintext));
    assert!(decrypt_vault_payload(&kek, &sealed_b)
        .unwrap()
        .eq(plaintext));
}

#[test]
fn test_vault_corruption_fails_authentication() {
    let kek = [0x44u8; 32];
    let plaintext = b"sensitive vault contents";
    let sealed = encrypt_vault_payload(&kek, plaintext).unwrap();

    let mut tampered_body = sealed.clone();
    let mid = 12 + (tampered_body.len() - 12) / 2;
    tampered_body[mid] ^= 0x01;
    assert!(matches!(
        decrypt_vault_payload(&kek, &tampered_body),
        Err(CryptoError::CipherOperation(_))
    ));

    let mut tampered_tag = sealed.clone();
    let last = tampered_tag.len() - 1;
    tampered_tag[last] ^= 0xFF;
    assert!(matches!(
        decrypt_vault_payload(&kek, &tampered_tag),
        Err(CryptoError::CipherOperation(_))
    ));

    let mut tampered_nonce = sealed.clone();
    tampered_nonce[0] ^= 0x80;
    assert!(decrypt_vault_payload(&kek, &tampered_nonce).is_err());

    let wrong_kek = [0x45u8; 32];
    assert!(decrypt_vault_payload(&wrong_kek, &sealed).is_err());

    let truncated = &sealed[..20];
    assert!(matches!(
        decrypt_vault_payload(&kek, truncated),
        Err(CryptoError::InvalidInput(_))
    ));
}

#[test]
fn test_zeroization_on_drop() {
    let seed = [0xA5u8; 32];
    let identity = Box::new(derive_identity_from_prf(&seed, 3).unwrap());
    let ed_ptr = identity.ed25519_priv_bytes.as_ptr();
    let secp_ptr = identity.secp256k1_priv_bytes.as_ptr();
    assert!(identity.ed25519_priv_bytes.iter().any(|&b| b != 0));
    assert!(identity.secp256k1_priv_bytes.iter().any(|&b| b != 0));

    drop(identity);

    unsafe {
        let ed_view = std::slice::from_raw_parts(ed_ptr, 32);
        assert!(
            ed_view.iter().all(|&b| b == 0),
            "ed25519 private bytes were not zeroized on drop"
        );
        let secp_view = std::slice::from_raw_parts(secp_ptr, 32);
        assert!(
            secp_view.iter().all(|&b| b == 0),
            "secp256k1 private bytes were not zeroized on drop"
        );
    }
}

#[test]
fn test_ffi_derive_identity_envelope() {
    let ptr = derive_identity_from_prf_ffi(TEST_SEED.as_ptr(), 32, 7);
    assert!(!ptr.is_null());
    let payload = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_str().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(payload).unwrap();

    assert_eq!(parsed["valid"], true);
    assert!(parsed["did"].as_str().unwrap().starts_with("did:key:z6Mk"));
    assert_eq!(parsed["nostr_pubkey_hex"].as_str().unwrap().len(), 64);
    assert!(parsed["error"].is_null());
    assert!(parsed.get("private_key").is_none());

    free_string(ptr);
}

#[test]
fn test_ffi_derive_identity_rejects_bad_input() {
    let ptr = derive_identity_from_prf_ffi(std::ptr::null(), 0, 0);
    assert!(!ptr.is_null());
    let parsed: serde_json::Value =
        serde_json::from_str(unsafe { std::ffi::CStr::from_ptr(ptr) }.to_str().unwrap()).unwrap();
    assert_eq!(parsed["valid"], false);
    assert!(!parsed["error"].as_str().unwrap().is_empty());
    free_string(ptr);

    let short_seed = [0x77u8; 16];
    let ptr = derive_identity_from_prf_ffi(short_seed.as_ptr(), 16, 0);
    assert!(!ptr.is_null());
    let parsed: serde_json::Value =
        serde_json::from_str(unsafe { std::ffi::CStr::from_ptr(ptr) }.to_str().unwrap()).unwrap();
    assert_eq!(parsed["valid"], false);
    assert!(parsed["error"].as_str().unwrap().contains("32"));
    free_string(ptr);
}

#[test]
fn test_ffi_vault_roundtrip() {
    let kek = [0x99u8; 32];
    let plaintext = br#"{"vault":"iyou_home","keys":["a","b"]}"#;

    let enc_ptr = encrypt_vault_payload_ffi(kek.as_ptr(), plaintext.as_ptr(), plaintext.len());
    assert!(!enc_ptr.is_null());
    let enc_json: serde_json::Value = serde_json::from_str(
        unsafe { std::ffi::CStr::from_ptr(enc_ptr) }
            .to_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(enc_json["valid"], true);
    assert!(enc_json["error"].is_null());

    let ciphertext = hex::decode(enc_json["ciphertext_hex"].as_str().unwrap()).expect("valid hex");
    assert_eq!(ciphertext.len(), plaintext.len() + HEADER_LEN);
    free_string(enc_ptr);

    let dec_ptr = decrypt_vault_payload_ffi(kek.as_ptr(), ciphertext.as_ptr(), ciphertext.len());
    assert!(!dec_ptr.is_null());
    let dec_json: serde_json::Value = serde_json::from_str(
        unsafe { std::ffi::CStr::from_ptr(dec_ptr) }
            .to_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(dec_json["valid"], true);
    assert_eq!(
        dec_json["plaintext_utf8"],
        serde_json::json!(String::from_utf8_lossy(plaintext))
    );
    free_string(dec_ptr);

    let mut corrupted = ciphertext.clone();
    corrupted[13] ^= 0x02;
    let bad_ptr = decrypt_vault_payload_ffi(kek.as_ptr(), corrupted.as_ptr(), corrupted.len());
    let bad_json: serde_json::Value = serde_json::from_str(
        unsafe { std::ffi::CStr::from_ptr(bad_ptr) }
            .to_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(bad_json["valid"], false);
    assert!(!bad_json["error"].as_str().unwrap().is_empty());
    free_string(bad_ptr);
}

#[test]
fn test_ffi_vault_rejects_bad_kek_pointers() {
    let null_ptr = encrypt_vault_payload_ffi(std::ptr::null(), b"x".as_ptr(), 1);
    assert!(!null_ptr.is_null());
    let parsed: serde_json::Value = serde_json::from_str(
        unsafe { std::ffi::CStr::from_ptr(null_ptr) }
            .to_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(parsed["valid"], false);
    free_string(null_ptr);

    let bad_kek = [0u8; 16];
    let ptr = decrypt_vault_payload_ffi(bad_kek.as_ptr(), [0u8; 28].as_ptr(), 28);
    assert!(!ptr.is_null());
    let parsed: serde_json::Value =
        serde_json::from_str(unsafe { std::ffi::CStr::from_ptr(ptr) }.to_str().unwrap()).unwrap();
    assert_eq!(parsed["valid"], false);
    free_string(ptr);
}
