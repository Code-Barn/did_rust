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
    derive_dependent_subkeys, derive_ed25519_did, derive_nostr_keypair, DependentDerivedKeypair,
};
use did_rust::{derive_dependent_subkeys_ffi, free_string};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{FieldBytes, SecretKey};
use sha2::{Digest, Sha256};

const TEST_SEED: [u8; 32] = [
    0x5a, 0xf2, 0x11, 0x9c, 0xe3, 0x40, 0xab, 0x71, 0xd8, 0x02, 0x66, 0x1b, 0xfa, 0x93, 0x55, 0xc4,
    0x7e, 0x10, 0x83, 0x2d, 0xb9, 0x64, 0xef, 0x07, 0x3c, 0xa1, 0x58, 0xcc, 0x20, 0xfd, 0x91, 0x36,
];

#[test]
fn test_dependent_derivation_deterministic() {
    let subkeys_a: DependentDerivedKeypair = derive_dependent_subkeys(&TEST_SEED, 0).unwrap();
    let subkeys_b: DependentDerivedKeypair = derive_dependent_subkeys(&TEST_SEED, 0).unwrap();

    assert_eq!(subkeys_a.did, subkeys_b.did);
    assert_eq!(subkeys_a.nostr_pubkey_hex, subkeys_b.nostr_pubkey_hex);
    assert_eq!(
        subkeys_a.ed25519_signing_key_bytes,
        subkeys_b.ed25519_signing_key_bytes
    );
    assert_eq!(
        subkeys_a.secp256k1_signing_key_bytes,
        subkeys_b.secp256k1_signing_key_bytes
    );
    assert_eq!(subkeys_a, subkeys_b);

    // Also verify deterministic across non-zero index
    let subkeys_42_a = derive_dependent_subkeys(&TEST_SEED, 42).unwrap();
    let subkeys_42_b = derive_dependent_subkeys(&TEST_SEED, 42).unwrap();
    assert_eq!(subkeys_42_a, subkeys_42_b);
}

#[test]
fn test_dependent_domain_separation() {
    let (parent_anchor_did, parent_anchor_ed_priv) = derive_ed25519_did(&TEST_SEED, 0).unwrap();
    let dependent = derive_dependent_subkeys(&TEST_SEED, 0).unwrap();

    // Direct requirement: assert dependent_did != parent_anchor_did
    assert_ne!(dependent.did, parent_anchor_did);
    assert_ne!(dependent.ed25519_signing_key_bytes, parent_anchor_ed_priv);

    // Domain separation for Nostr keypair
    let (parent_nostr_pubkey, parent_nostr_secp_priv) =
        derive_nostr_keypair(&TEST_SEED, 0).unwrap();
    assert_ne!(dependent.nostr_pubkey_hex, parent_nostr_pubkey);
    assert_ne!(
        dependent.secp256k1_signing_key_bytes,
        parent_nostr_secp_priv
    );

    // Cross-curve domain separation within dependent subkeys
    assert_ne!(
        dependent.ed25519_signing_key_bytes,
        dependent.secp256k1_signing_key_bytes
    );

    // Verify hash level domain separation against explicit manual hash constructions
    let index_le = 0u32.to_le_bytes();

    let expected_ed_seed: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(TEST_SEED);
        hasher.update(b"iyou/dependent/");
        hasher.update(index_le);
        hasher.finalize().into()
    };
    assert_eq!(dependent.ed25519_signing_key_bytes, expected_ed_seed);

    let expected_secp_scalar: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(b"secp256k1-nostr/dependent/");
        hasher.update(TEST_SEED);
        hasher.update(index_le);
        hasher.finalize().into()
    };
    assert_eq!(dependent.secp256k1_signing_key_bytes, expected_secp_scalar);
}

#[test]
fn test_dependent_index_sensitivity() {
    let idx0 = derive_dependent_subkeys(&TEST_SEED, 0).unwrap();
    let idx1 = derive_dependent_subkeys(&TEST_SEED, 1).unwrap();

    assert_ne!(idx0.did, idx1.did);
    assert_ne!(idx0.nostr_pubkey_hex, idx1.nostr_pubkey_hex);
    assert_ne!(
        idx0.ed25519_signing_key_bytes,
        idx1.ed25519_signing_key_bytes
    );
    assert_ne!(
        idx0.secp256k1_signing_key_bytes,
        idx1.secp256k1_signing_key_bytes
    );
}

#[test]
fn test_dependent_seed_sensitivity() {
    let mut other_seed = TEST_SEED;
    other_seed[0] ^= 0x01;

    let subkeys_orig = derive_dependent_subkeys(&TEST_SEED, 0).unwrap();
    let subkeys_other = derive_dependent_subkeys(&other_seed, 0).unwrap();

    assert_ne!(subkeys_orig.did, subkeys_other.did);
    assert_ne!(
        subkeys_orig.nostr_pubkey_hex,
        subkeys_other.nostr_pubkey_hex
    );
    assert_ne!(
        subkeys_orig.ed25519_signing_key_bytes,
        subkeys_other.ed25519_signing_key_bytes
    );
    assert_ne!(
        subkeys_orig.secp256k1_signing_key_bytes,
        subkeys_other.secp256k1_signing_key_bytes
    );
}

#[test]
fn test_dependent_ed25519_did_format_and_verification() {
    let subkeys = derive_dependent_subkeys(&TEST_SEED, 0).unwrap();
    assert!(subkeys.did.starts_with("did:key:z6Mk"));

    let body = subkeys.did.strip_prefix("did:key:z").unwrap();
    let decoded = bs58::decode(body).into_vec().unwrap();
    assert_eq!(decoded.len(), 34);
    assert_eq!(&decoded[..2], &[0xed, 0x01]);

    let signing_key = SigningKey::from_bytes(&subkeys.ed25519_signing_key_bytes);
    let verifying_key = signing_key.verifying_key();
    assert_eq!(&decoded[2..], verifying_key.as_bytes().as_slice());

    // Test signing and verifying a message with derived keypair
    let msg = b"parent-stewarded dependent message";
    let signature = signing_key.sign(msg);
    assert!(verifying_key.verify(msg, &signature).is_ok());

    // Verifying with parsed multicodec key matches
    let parsed_verifying_key =
        VerifyingKey::from_bytes((&decoded[2..34]).try_into().unwrap()).unwrap();
    assert!(parsed_verifying_key.verify(msg, &signature).is_ok());
}

#[test]
fn test_dependent_nostr_pubkey_format_and_verification() {
    let subkeys = derive_dependent_subkeys(&TEST_SEED, 0).unwrap();
    assert_eq!(subkeys.nostr_pubkey_hex.len(), 64);
    assert!(subkeys
        .nostr_pubkey_hex
        .chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));

    let secret =
        SecretKey::from_bytes(&FieldBytes::from(subkeys.secp256k1_signing_key_bytes)).unwrap();
    let encoded = secret.public_key().to_encoded_point(false);
    let x_only = &encoded.as_ref()[1..33];
    assert_eq!(hex::encode(x_only), subkeys.nostr_pubkey_hex);
}

#[test]
fn test_dependent_zeroization_on_drop() {
    let seed = [0x5Cu8; 32];
    let subkeys = Box::new(derive_dependent_subkeys(&seed, 7).unwrap());
    let ed_ptr = subkeys.ed25519_signing_key_bytes.as_ptr();
    let secp_ptr = subkeys.secp256k1_signing_key_bytes.as_ptr();

    assert!(subkeys.ed25519_signing_key_bytes.iter().any(|&b| b != 0));
    assert!(subkeys.secp256k1_signing_key_bytes.iter().any(|&b| b != 0));

    drop(subkeys);

    unsafe {
        let ed_view = std::slice::from_raw_parts(ed_ptr, 32);
        assert!(
            ed_view.iter().all(|&b| b == 0),
            "ed25519 signing key bytes were not zeroized on drop"
        );
        let secp_view = std::slice::from_raw_parts(secp_ptr, 32);
        assert!(
            secp_view.iter().all(|&b| b == 0),
            "secp256k1 signing key bytes were not zeroized on drop"
        );
    }
}

#[test]
fn test_dependent_ffi_roundtrip() {
    let ptr = derive_dependent_subkeys_ffi(TEST_SEED.as_ptr(), 32, 0);
    assert!(!ptr.is_null());

    let payload = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_str().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(payload).unwrap();

    assert_eq!(parsed["valid"], true);
    assert!(parsed["did"].as_str().unwrap().starts_with("did:key:z6Mk"));
    assert_eq!(parsed["nostr_pubkey_hex"].as_str().unwrap().len(), 64);
    assert!(parsed["error"].is_null());

    // Ensure private keys are NEVER leaked in FFI response
    assert!(parsed.get("private_key").is_none());
    assert!(parsed.get("ed25519_signing_key_bytes").is_none());
    assert!(parsed.get("secp256k1_signing_key_bytes").is_none());

    // Matches Rust direct call
    let direct = derive_dependent_subkeys(&TEST_SEED, 0).unwrap();
    assert_eq!(parsed["did"], direct.did);
    assert_eq!(parsed["nostr_pubkey_hex"], direct.nostr_pubkey_hex);

    free_string(ptr);
}

#[test]
fn test_dependent_ffi_rejects_bad_input() {
    // Null pointer
    let null_ptr = derive_dependent_subkeys_ffi(std::ptr::null(), 32, 0);
    assert!(!null_ptr.is_null());
    let parsed: serde_json::Value = serde_json::from_str(
        unsafe { std::ffi::CStr::from_ptr(null_ptr) }
            .to_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(parsed["valid"], false);
    assert!(parsed["error"].as_str().unwrap().contains("Null pointer"));
    free_string(null_ptr);

    // Invalid length: shorter than 32
    let short_seed = [0x11u8; 16];
    let short_ptr = derive_dependent_subkeys_ffi(short_seed.as_ptr(), 16, 0);
    assert!(!short_ptr.is_null());
    let parsed: serde_json::Value = serde_json::from_str(
        unsafe { std::ffi::CStr::from_ptr(short_ptr) }
            .to_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(parsed["valid"], false);
    assert!(parsed["error"].as_str().unwrap().contains("32"));
    free_string(short_ptr);

    // Invalid length: longer than 32
    let long_seed = [0x22u8; 64];
    let long_ptr = derive_dependent_subkeys_ffi(long_seed.as_ptr(), 64, 0);
    assert!(!long_ptr.is_null());
    let parsed: serde_json::Value = serde_json::from_str(
        unsafe { std::ffi::CStr::from_ptr(long_ptr) }
            .to_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(parsed["valid"], false);
    assert!(parsed["error"].as_str().unwrap().contains("32"));
    free_string(long_ptr);
}
