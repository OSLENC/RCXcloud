//! AES-256-GCM — AEAD ONLY.
//!
//! TRUST LEVEL: Secure Core

use crate::memory::GuardedKey32;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use aes_gcm::aead::AeadInPlace;

/// AES-GCM standard nonce length (96-bit).
pub const NONCE_LEN: usize = 12;

/// AES-GCM authentication tag length.
pub const TAG_LEN: usize = 16;

/* ───────────── ENCRYPT ───────────── */

pub fn seal(
    key: &GuardedKey32,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
    out: &mut [u8],
) -> Result<(), ()> {
    let pt_len = plaintext.len();
    let required = pt_len + TAG_LEN;

    if out.len() != required {
        out.fill(0);
        return Err(());
    }

    let cipher = Aes256Gcm::new_from_slice(key.borrow()).map_err(|_| {
        out.fill(0);
        ()
    })?;

    // Copy plaintext into output buffer
    out[..pt_len].copy_from_slice(plaintext);

    let nonce = Nonce::from_slice(nonce);

    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, &mut out[..pt_len])
        .map_err(|_| {
            out[..pt_len].fill(0);
            ()
        })?;

    out[pt_len..].copy_from_slice(tag.as_slice());
    Ok(())
}

/* ───────────── DECRYPT ───────────── */

pub fn open(
    key: &GuardedKey32,
    nonce: &[u8; NONCE_LEN],
    input: &[u8],
    aad: &[u8],
    out: &mut [u8],
) -> bool {
    if input.len() < TAG_LEN {
        out.fill(0);
        return false;
    }

    let ct_len = input.len() - TAG_LEN;

    if out.len() != ct_len {
        out.fill(0);
        return false;
    }

    let cipher = match Aes256Gcm::new_from_slice(key.borrow()) {
        Ok(c) => c,
        Err(_) => {
            out.fill(0);
            return false;
        }
    };

    out.copy_from_slice(&input[..ct_len]);

    let nonce = Nonce::from_slice(nonce);
    let tag = Tag::from_slice(&input[ct_len..]);

    if cipher
        .decrypt_in_place_detached(nonce, aad, out, tag)
        .is_err()
    {
        out.fill(0);
        return false;
    }

    true
}