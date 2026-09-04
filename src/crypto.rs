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

use ed25519_dalek::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{FieldBytes, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const NOSTR_DOMAIN: &[u8] = b"secp256k1-nostr";
const DEPENDENT_ED25519_DOMAIN: &[u8] = b"iyou/dependent/";
const DEPENDENT_NOSTR_DOMAIN: &[u8] = b"secp256k1-nostr/dependent/";
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];
const SCALAR_ATTEMPTS: u8 = 255;

#[derive(Debug)]
pub enum CryptoError {
    ScalarDerivationFailed,
    InvalidInput(String),
    CipherOperation(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::ScalarDerivationFailed => {
                write!(f, "Failed to derive a valid scalar from seed material")
            }
            CryptoError::InvalidInput(msg) => write!(f, "Invalid input: {msg}"),
            CryptoError::CipherOperation(msg) => write!(f, "Cipher operation failed: {msg}"),
        }
    }
}

impl std::error::Error for CryptoError {}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedIdentity {
    pub did: String,
    pub nostr_pubkey_hex: String,
    pub ed25519_priv_bytes: [u8; 32],
    pub secp256k1_priv_bytes: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct DependentDerivedKeypair {
    pub ed25519_signing_key_bytes: [u8; 32],
    pub did: String,
    pub secp256k1_signing_key_bytes: [u8; 32],
    pub nostr_pubkey_hex: String,
}

pub fn derive_ed25519_did(
    root_seed: &[u8; 32],
    index: u32,
) -> Result<(String, [u8; 32]), CryptoError> {
    let priv_bytes = sha256_concat(&[root_seed.as_slice(), &index.to_le_bytes()]);
    let signing_key = SigningKey::from_bytes(&priv_bytes);
    let public = signing_key.verifying_key();

    let mut multicodec = [0u8; 34];
    multicodec[..2].copy_from_slice(&ED25519_MULTICODEC);
    multicodec[2..].copy_from_slice(public.as_bytes());

    let did = format!("did:key:z{}", bs58::encode(multicodec).into_string());
    Ok((did, priv_bytes))
}

pub fn derive_nostr_keypair(
    root_seed: &[u8; 32],
    index: u32,
) -> Result<(String, [u8; 32]), CryptoError> {
    let priv_bytes = derive_secp256k1_scalar(root_seed, index)?;
    let secret_key = SecretKey::from_bytes(&FieldBytes::from(priv_bytes))
        .map_err(|_| CryptoError::ScalarDerivationFailed)?;
    let encoded_point = secret_key.public_key().to_encoded_point(false);
    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&encoded_point.as_ref()[1..33]);

    Ok((hex::encode(x_only), priv_bytes))
}

pub fn derive_identity_from_prf(
    prf_seed: &[u8; 32],
    index: u32,
) -> Result<DerivedIdentity, CryptoError> {
    let (did, ed25519_priv_bytes) = derive_ed25519_did(prf_seed, index)?;
    let (nostr_pubkey_hex, secp256k1_priv_bytes) = derive_nostr_keypair(prf_seed, index)?;

    Ok(DerivedIdentity {
        did,
        nostr_pubkey_hex,
        ed25519_priv_bytes,
        secp256k1_priv_bytes,
    })
}

pub fn derive_dependent_subkeys(
    root_seed: &[u8; 32],
    dependent_index: u32,
) -> Result<DependentDerivedKeypair, CryptoError> {
    // child_ed25519_seed = SHA-256(root_seed || "iyou/dependent/" || LE32(dependent_index))
    let mut ed_hasher = Sha256::new();
    ed_hasher.update(root_seed);
    ed_hasher.update(DEPENDENT_ED25519_DOMAIN);
    ed_hasher.update(dependent_index.to_le_bytes());
    let ed_seed: [u8; 32] = ed_hasher.finalize().into();
    let ed_seed = Zeroizing::new(ed_seed);

    let signing_key = SigningKey::from_bytes(&ed_seed);
    let public = signing_key.verifying_key();

    let mut multicodec = [0u8; 34];
    multicodec[..2].copy_from_slice(&ED25519_MULTICODEC);
    multicodec[2..].copy_from_slice(public.as_bytes());

    let did = format!("did:key:z{}", bs58::encode(multicodec).into_string());

    let secp_scalar = derive_dependent_secp256k1_scalar(root_seed, dependent_index)?;
    let secret_key = SecretKey::from_bytes(&FieldBytes::from(*secp_scalar))
        .map_err(|_| CryptoError::ScalarDerivationFailed)?;
    let encoded_point = secret_key.public_key().to_encoded_point(false);
    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&encoded_point.as_ref()[1..33]);
    let nostr_pubkey_hex = hex::encode(x_only);

    Ok(DependentDerivedKeypair {
        ed25519_signing_key_bytes: *ed_seed,
        did,
        secp256k1_signing_key_bytes: *secp_scalar,
        nostr_pubkey_hex,
    })
}

fn derive_dependent_secp256k1_scalar(
    root_seed: &[u8; 32],
    index: u32,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    for attempt in 0..=SCALAR_ATTEMPTS {
        let index_le = index.to_le_bytes();
        let mut hasher = Sha256::new();
        hasher.update(DEPENDENT_NOSTR_DOMAIN);
        hasher.update(root_seed);
        hasher.update(index_le);
        if attempt > 0 {
            hasher.update(std::slice::from_ref(&attempt));
        }
        let candidate: [u8; 32] = hasher.finalize().into();
        let candidate = Zeroizing::new(candidate);
        if SecretKey::from_bytes(&FieldBytes::from(*candidate)).is_ok() {
            return Ok(candidate);
        }
    }
    Err(CryptoError::ScalarDerivationFailed)
}

fn derive_secp256k1_scalar(root_seed: &[u8; 32], index: u32) -> Result<[u8; 32], CryptoError> {
    for attempt in 0..=SCALAR_ATTEMPTS {
        let index_le = index.to_le_bytes();
        let mut inputs: Vec<&[u8]> = vec![NOSTR_DOMAIN, root_seed.as_slice(), &index_le];
        if attempt > 0 {
            inputs.push(std::slice::from_ref(&attempt));
        }
        let candidate = sha256_concat(&inputs);
        if SecretKey::from_bytes(&FieldBytes::from(candidate)).is_ok() {
            return Ok(candidate);
        }
    }
    Err(CryptoError::ScalarDerivationFailed)
}

fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let out = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}
