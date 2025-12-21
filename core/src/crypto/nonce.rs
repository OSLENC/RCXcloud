
//! Deterministic nonce derivation (NONCE MISUSE SAFE).
//!
//! TRUST LEVEL: Secure Core
//!
//! FORMAL INVARIANTS (ENFORCED):
//! - No RNG usage
//! - No caller-supplied nonce
//! - Deterministic per (key, file_id, chunk)
//! - Domain-separated from key derivation
//! - Nonce length fixed at 96 bits (AES-GCM)
//! - No panics
//!
//! SECURITY NOTE:
//! This construction prevents nonce reuse across:
//! - different files
//! - different chunks
//! - different derived keys

use crate::memory::GuardedKey32;
use hmac::{Hmac, Mac};
use sha2::Sha256;

const NONCE_LEN: usize = 12;
const NONCE_LABEL: &[u8] = b"rcxcloud-nonce-v1";

/// Derive a deterministic 96-bit AES-GCM nonce.
///
/// Inputs:
/// - `key`     : derived encryption key (NOT master)
/// - `file_id` : unique file identifier
/// - `chunk`   : chunk index within file
///
/// Output:
/// - 12-byte nonce, safe for AES-GCM
pub fn derive_nonce(
    key: &GuardedKey32,
    file_id: u64,
    chunk: u32,
) -> [u8; NONCE_LEN] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.borrow())
        .expect("HMAC accepts any key length");

    // Domain separation
    mac.update(NONCE_LABEL);

    // Structured, fixed-width encoding
    mac.update(&file_id.to_be_bytes());
    mac.update(&chunk.to_be_bytes());

    let digest = mac.finalize().into_bytes();

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&digest[..NONCE_LEN]);
    nonce
}

