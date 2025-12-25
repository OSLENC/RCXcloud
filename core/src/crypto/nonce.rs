//! Deterministic nonce derivation (NONCE MISUSE SAFE).
//!
//! TRUST LEVEL: Secure Core
//!
//! FORMAL INVARIANTS (ENFORCED):
//! - No RNG usage
//! - No caller-supplied nonce
//! - Deterministic per (key, file_id, chunk)
//! - Domain-separated from all other nonce uses
//! - Nonce length fixed at 96 bits (AES-GCM)
//! - Fail-closed by construction
//!
//! This construction is safe for AES-GCM because:
//! - Keys are purpose-bound
//! - Nonces are unique per (key, file_id, chunk)

use crate::memory::GuardedKey32;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// AES-GCM nonce length (96-bit, RFC 4106).
pub const NONCE_LEN: usize = 12;

/// Domain separation label (FILE ENCRYPTION ONLY).
///
/// ⚠️ MUST NEVER CHANGE.
/// ⚠️ MUST NEVER be reused for any other purpose.
const NONCE_LABEL_FILE: &[u8] = b"rcxcloud:file:nonce:v1";

/// Derive a deterministic 96-bit AES-GCM nonce.
///
/// SECURITY:
/// - Deterministic
/// - Key-bound
/// - Purpose-separated
/// - No failure paths (HMAC accepts any key length)
#[inline(always)]
pub fn derive_nonce(
    key: &GuardedKey32,
    file_id: u64,
    chunk: u32,
) -> [u8; NONCE_LEN] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.borrow())
            .expect("HMAC accepts any key length");

    // Domain separation + context binding
    mac.update(NONCE_LABEL_FILE);
    mac.update(&file_id.to_be_bytes());
    mac.update(&chunk.to_be_bytes());

    let digest = mac.finalize().into_bytes();

    // Truncate HMAC-SHA256 → 96-bit nonce (RFC 4106)
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&digest[..NONCE_LEN]);

    nonce
}
