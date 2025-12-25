
//! Device fingerprint (NON-SECRET, STABLE).
//!
//! TRUST LEVEL: Secure Core

#![deny(clippy::derive_debug)]

use crate::integrity::hash::hash_sha256;

/// Canonical device fingerprint.
///
/// SECURITY:
/// - Non-secret
/// - Stable
/// - Fixed-width
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DeviceFingerprint(u64);

impl DeviceFingerprint {
    /// Create fingerprint from canonical device material.
    ///
    /// SECURITY:
    /// - Deterministic
    /// - One-way hash
    /// - Stable across reboots
    pub fn from_material(material: &[u8]) -> Self {
        let hash = hash_sha256(material);

        // Truncate SHA-256 → u64 (BE)
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&hash.as_ref()[..8]);

        Self(u64::from_be_bytes(buf))
    }

    /// Reconstruct fingerprint from stored value.
    ///
    /// SECURITY:
    /// - Deterministic
    /// - No hashing
    /// - No ambiguity
    pub(crate) fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// Big-endian bytes.
    ///
    /// Used for:
    /// - HKDF context
    /// - AAD binding
    #[inline(always)]
    pub fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Numeric fingerprint value.
    ///
    /// Used for:
    /// - derive_key(context)
    #[inline(always)]
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl core::fmt::Debug for DeviceFingerprint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("<DeviceFingerprint>")
    }
}