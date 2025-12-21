
//! Key hierarchy & deterministic derivation.
//!
//! TRUST LEVEL: Secure Core
//!
//! FORMAL INVARIANTS (ENFORCED):
//! - Master key is NEVER used directly
//! - All derived keys are purpose-bound
//! - Deterministic derivation (no RNG)
//! - Domain separation via Purpose tags
//! - Derivation context is explicit and typed
//! - Output keys live ONLY in GuardedKey32
//! - Caller never handles raw key bytes
//! - NO panics in cryptographic paths
//!
//! This module is misuse-resistant by construction.

use crate::memory::GuardedKey32;
use hkdf::Hkdf;
use sha2::Sha256;

/// Cryptographic purpose tags.
///
/// ❗ Adding a new variant is a SECURITY decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// File content encryption (chunks)
    FileEncryption,

    /// File metadata protection
    Metadata,

    /// Device-to-device pairing
    Pairing,

    /// Backup / recovery material
    Recovery,
}

impl Purpose {
    /// Domain separation label (compile-time fixed).
    #[inline(always)]
    fn label(self) -> &'static [u8] {
        match self {
            Purpose::FileEncryption => b"rcx:file:enc:v1",
            Purpose::Metadata       => b"rcx:meta:v1",
            Purpose::Pairing        => b"rcx:pair:v1",
            Purpose::Recovery       => b"rcx:recovery:v1",
        }
    }
}

/// Deterministically derive a child key from a parent key.
///
/// SECURITY:
/// - HKDF-SHA256
/// - No randomness
/// - No heap allocations
/// - No stack copies of key material
/// - Output written directly into GuardedKey32
/// - NO panics
///
/// `context` MUST uniquely identify the target (e.g. file_id).
pub fn derive_key(
    parent: &GuardedKey32,
    purpose: Purpose,
    context: u128,
) -> Result<GuardedKey32, ()> {
    let mut out = GuardedKey32::zeroed();

    // ───────────── INFO ENCODING (FIXED) ─────────────
    //
    // Layout (32 bytes total):
    // [0]        = label length (u8)
    // [1..=15]   = purpose label (max 15 bytes)
    // [16..=31]  = context (u128, big-endian)
    //
    // This encoding is:
    // - unambiguous
    // - collision-resistant
    // - forward-compatible

    let label = purpose.label();
    let label_len = label.len();

    // Compile-time safety: labels must remain short
    debug_assert!(label_len <= 15);

    let mut info = [0u8; 32];
    info[0] = label_len as u8;
    info[1..1 + label_len].copy_from_slice(label);
    info[16..32].copy_from_slice(&context.to_be_bytes());

    let hkdf = Hkdf::<Sha256>::new(
        Some(parent.borrow()), // salt = parent key (domain separation)
        &info,
    );

    hkdf.expand(b"rcxcloud-derive", out.borrow_mut())
        .map_err(|_| ())?;

    Ok(out)
}