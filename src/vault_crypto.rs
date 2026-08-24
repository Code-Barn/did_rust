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

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use crate::crypto::CryptoError;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const HEADER_LEN: usize = NONCE_LEN + TAG_LEN;

impl From<chacha20poly1305::aead::Error> for CryptoError {
    fn from(_: chacha20poly1305::aead::Error) -> Self {
        CryptoError::CipherOperation("AEAD authentication failed".to_string())
    }
}

pub fn encrypt_vault_payload(kek: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(kek));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let sealed = cipher.encrypt(&nonce, plaintext)?;

    let mut output = Vec::with_capacity(NONCE_LEN + sealed.len());
    output.extend_from_slice(nonce.as_slice());
    output.extend_from_slice(&sealed);
    Ok(output)
}

pub fn decrypt_vault_payload(
    kek: &[u8; 32],
    ciphertext_with_nonce: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext_with_nonce.len() < HEADER_LEN {
        return Err(CryptoError::InvalidInput(format!(
            "ciphertext too short: expected at least {HEADER_LEN} bytes, got {}",
            ciphertext_with_nonce.len()
        )));
    }
    let (nonce_bytes, sealed) = ciphertext_with_nonce.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(kek));
    let plaintext = cipher.decrypt(Nonce::from_slice(nonce_bytes), sealed)?;
    Ok(plaintext)
}
