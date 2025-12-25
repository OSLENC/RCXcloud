//! Key hierarchy & deterministic derivation.
//!
//! TRUST LEVEL: Secure Core
//!
//! FORMAL INVARIANTS (ENFORCED):
//! - Parent key is NEVER used directly
//! - All derived keys are purpose-bound
//! - Deterministic derivation (no RNG)
//! - Domain separation via Purpose tags
//! - Derivation context is explicit and typed
//! - Output keys are written IN-PLACE only
//! - Caller never handles raw key bytes
//! - NO panics in cryptographic paths

use crate::memory::GuardedKey32;
use hkdf::Hkdf;
use sha2::Sha256;

/// Cryptographic purpose tags.
///
/// ❗ Adding or modifying a variant is a SECURITY DECISION.
/// ❗ Labels are part of the cryptographic protocol.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// File chunk encryption keys
    FileEncryption,

    /// File metadata protection
    Metadata,

    /// Device-to-device pairing
    Pairing,

    /// Recovery / kill / admin control
    Recovery,
}

impl Purpose {
    /// Fixed domain-separation label.
    ///
    /// ⚠️ MUST remain stable forever.
    /// Changing this breaks backward compatibility.
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

/// Deterministically derive a child key into an existing buffer.
///
/// SECURITY:
/// - HKDF-SHA256
/// - Parent key used as IKM (correct HKDF usage)
/// - No randomness
/// - No heap allocations
/// - Output written directly into GuardedKey32
/// - Fail-closed on error
///
/// `context` MUST uniquely identify the target
/// (e.g. file_id, device_id hash, registry fingerprint).
#[inline(always)]
pub fn derive_key(
    parent: &GuardedKey32,
    purpose: Purpose,
    context: u64,
    out: &mut GuardedKey32,
) -> Result<(), ()> {
    let label = purpose.label();

    // Hard safety limit: labels must stay short & fixed
    if label.len() > 32 {
        return Err(());
    }

    // ───────────── INFO ENCODING ─────────────
    //
    // info = label || context_be
    //
    // Properties:
    // - fixed-width
    // - unambiguous
    // - deterministic
    // - forward-auditable
    let mut info = [0u8; 32 + 8];
    info[..label.len()].copy_from_slice(label);
    info[label.len()..label.len() + 8]
        .copy_from_slice(&context.to_be_bytes());

    // HKDF extract+expand
    // - No salt (parent key already high entropy)
    // - Parent key is IKM (never used directly elsewhere)
    let hkdf = Hkdf::<Sha256>::new(
        None,
        parent.borrow(),
    );
// NOTE: salt intentionally None; parent key is high-entropy IKM

    hkdf.expand(
        &info[..label.len() + 8],
        out.borrow_mut(),
    )
    .map_err(|_| ())
}
