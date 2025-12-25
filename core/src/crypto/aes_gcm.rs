//! AES-256-GCM — AEAD ONLY.
//!
//! TRUST LEVEL: Secure Core
//!
//! ENFORCED INVARIANTS:
//! - AEAD only (no raw encrypt/decrypt)
//! - Nonce is caller-provided (derived, never random here)
//! - Verify-then-decrypt
//! - No plaintext written on authentication failure
//! - Output buffers wiped on ALL failures
//! - Fail-closed
//! - No panics

use crate::memory::GuardedKey32;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use aead::{AeadInPlace, Payload};

/// AES-GCM standard nonce length (96-bit).
pub const NONCE_LEN: usize = 12;

/// AES-GCM authentication tag length.
pub const TAG_LEN: usize = 16;

/* ───────────── ENCRYPT ───────────── */

/// Encrypt + authenticate.
///
/// Output layout:
/// `[ ciphertext | tag ]`
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

    let cipher = Aes256Gcm::new_from_slice(key.borrow())
        .map_err(|_| {
            out.fill(0);
            ()
        })?;

    out[..pt_len].copy_from_slice(plaintext);

    let tag = cipher
        .encrypt_in_place_detached(
            Nonce::from_slice(nonce),
            Payload {
                msg: &mut out[..pt_len],
                aad,
            },
        )
        .map_err(|_| {
            out[..pt_len].fill(0);
            ()
        })?;

    out[pt_len..].copy_from_slice(tag.as_slice());
    Ok(())
}

/* ───────────── DECRYPT ───────────── */

/// Authenticate + decrypt.
///
/// INPUT layout:
/// `[ ciphertext | tag ]`
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

    let tag = Tag::from_slice(&input[ct_len..]);

    out.copy_from_slice(&input[..ct_len]);

    let res = cipher.decrypt_in_place_detached(
        Nonce::from_slice(nonce),
        Payload {
            msg: out,
            aad,
        },
        tag,
    );

    if res.is_err() {
        out.fill(0);
        return false;
    }

    true
}