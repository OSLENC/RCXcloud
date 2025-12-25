//! SHA-256 hashing (INTEGRITY ONLY).
//!
//! TRUST LEVEL: Secure Core
//!
//! IMPORTANT:
//! - Hash outputs are NOT secrets
//! - Hashes are NOT authentication
//! - Hashes are NOT MACs
//! - Hashes MUST NOT be used alone for security decisions
//!
//! This module exists ONLY to provide:
//! - deterministic integrity fingerprints
//! - equality comparison
//! - stable identifiers

use sha2::{Digest, Sha256};

/// Fixed-size SHA-256 hash output.
///
/// SECURITY NOTES:
/// - Non-secret
/// - Safe to store and compare
/// - Must remain opaque at boundaries
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HashOutput([u8; 32]);

impl HashOutput {
    /// Borrow raw hash bytes.
    #[inline(always)]
    pub fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Prevent accidental logging of full hash values.
///
/// Hashes are non-secret, but leaking them provides
/// unnecessary correlation and fingerprinting surface.
impl core::fmt::Debug for HashOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("<HashOutput>")
    }
}

/// Compute SHA-256 hash of arbitrary data.
///
/// SECURITY:
/// - Deterministic
/// - Stateless
/// - Stack-only
/// - No secrets involved
#[inline]
pub fn hash_sha256(data: &[u8]) -> HashOutput {
    let mut hasher = Sha256::new();
    hasher.update(data);

    let digest = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);

    HashOutput(out)
}
