
//! AES-256-GCM — AEAD ONLY.
//!
//! ENFORCED INVARIANTS:
//! - No raw encrypt/decrypt APIs
//! - Nonce is ALWAYS provided by caller (derived, not random)
//! - Verify-then-decrypt only
//! - No partial plaintext output on failure
//! - No panics

use crate::memory::GuardedKey32;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use aead::{AeadInPlace, Payload};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Encrypt + authenticate in-place.
///
/// Output format:
/// `[ ciphertext | tag (16) ]`
pub fn seal(
    key: &GuardedKey32,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
    out: &mut [u8],
) -> Result<(), ()> {
    if out.len() < plaintext.len() + TAG_LEN {
        return Err(());
    }

    let cipher = Aes256Gcm::new_from_slice(key.borrow()).map_err(|_| ())?;

    // Copy plaintext into output buffer
    out[..plaintext.len()].copy_from_slice(plaintext);

    let tag = cipher
        .encrypt_in_place_detached(
            Nonce::from_slice(nonce),
            Payload {
                msg: &mut out[..plaintext.len()],
                aad,
            },
        )
        .map_err(|_| ())?;

    out[plaintext.len()..plaintext.len() + TAG_LEN].copy_from_slice(tag.as_slice());

    Ok(())
}

/// Authenticate + decrypt in-place.
///
/// Returns:
/// - `true`  → authentication succeeded, plaintext written
/// - `false` → authentication failed, output is zeroed

pub fn open(
    key: &GuardedKey32,
    nonce: &[u8; NONCE_LEN],
    input: &[u8],
    aad: &[u8],
    out: &mut [u8],
) -> bool {
    if input.len() < TAG_LEN {
        return false;
    }

    let ct_len = input.len() - TAG_LEN;
    if out.len() < ct_len {
        return false;
    }

    let cipher = match Aes256Gcm::new_from_slice(key.borrow()) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let tag = Tag::from_slice(&input[ct_len..]);

    // Copy ciphertext into a temporary view of output,
    // but do NOT expose it unless auth succeeds
    out[..ct_len].copy_from_slice(&input[..ct_len]);

    let ok = cipher.decrypt_in_place_detached(
        Nonce::from_slice(nonce),
        Payload {
            msg: &mut out[..ct_len],
            aad,
        },
        tag,
    ).is_ok();

    if !ok {
        out[..ct_len].fill(0);
    }

    ok
}

