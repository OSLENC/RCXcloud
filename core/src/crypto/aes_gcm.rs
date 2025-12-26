//! AES-256-GCM wrapper (FIPS 197 / NIST SP 800-38D).
//!
//! TRUST LEVEL: Secure Core
//!
//! INVARIANTS:
//! - 96-bit Nonce (Fixed)
//! - 128-bit Tag (Fixed)
//! - Deterministic Nonce (enforced upstream)
//! - Typed AAD (enforced upstream)
//! - No panics
//! - No logging
//! - Fail closed

use crate::memory::GuardedKey32;
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

/// Encrypt plaintext into `dst`.
///
/// Returns ciphertext length (plaintext.len() + TAG_LEN).
pub fn encrypt(
    key: &GuardedKey32,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
    dst: &mut [u8],
) -> Result<usize, ()> {
    let required = plaintext.len() + TAG_LEN;
    if dst.len() < required {
        return Err(());
    }

    let cipher = Aes256Gcm::new(key.borrow().into());
    let nonce = Nonce::from_slice(nonce);

    // Copy plaintext into dst buffer
    dst[..plaintext.len()].copy_from_slice(plaintext);

    // Encrypt in place (appends tag)
    let ct_len = match cipher.encrypt_in_place_detached(
        nonce,
        aad,
        &mut dst[..plaintext.len()],
    ) {
        Ok(tag) => {
            dst[plaintext.len()..required].copy_from_slice(&tag);
            required
        }
        Err(_) => return Err(()),
    };

    Ok(ct_len)
}

/// Decrypt ciphertext into `dst`.
///
/// Returns plaintext length (ciphertext.len() - TAG_LEN).
pub fn decrypt(
    key: &GuardedKey32,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
    dst: &mut [u8],
) -> Result<usize, ()> {
    if ciphertext.len() < TAG_LEN {
        return Err(());
    }

    let pt_len = ciphertext.len() - TAG_LEN;
    if dst.len() < pt_len {
        return Err(());
    }

    let cipher = Aes256Gcm::new(key.borrow().into());
    let nonce = Nonce::from_slice(nonce);

    // Split ciphertext and tag
    dst[..pt_len].copy_from_slice(&ciphertext[..pt_len]);
    let tag = aes_gcm::Tag::from_slice(&ciphertext[pt_len..]);

    match cipher.decrypt_in_place_detached(
        nonce,
        aad,
        &mut dst[..pt_len],
        tag,
    ) {
        Ok(_) => Ok(pt_len),
        Err(_) => Err(()),
    }
}
