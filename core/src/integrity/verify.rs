//! Key integrity verification (Secure Core).
//!
//! PURPOSE:
//! Verify that a session key is cryptographically bound to
//! master recovery material.
//!
//! TRUST LEVEL: Secure Core
//!
//! SECURITY INVARIANTS (ENFORCED):
//! - GuardedKey32 ONLY
//! - Deterministic derivation
//! - Domain-separated from encryption
//! - Constant-time comparison
//! - Fail-closed on any error
//! - No panics

use crate::crypto::derive::{derive_key, Purpose};
use crate::memory::GuardedKey32;
use subtle::ConstantTimeEq;

/// Fixed integrity derivation context.
///
/// SECURITY:
/// - MUST remain stable forever
/// - Changing this breaks recovery compatibility
const INTEGRITY_CONTEXT: u64 = 0x494E544547524954; // "INTEGRIT";

/// Verify that `session` is correctly derived from `master`.
///
/// SECURITY:
/// - Uses Recovery domain separation
/// - Constant-time comparison
/// - Fail-closed on derivation error
pub fn verify_key_integrity(
    master: &GuardedKey32,
    session: &GuardedKey32,
) -> Result<(), IntegrityError> {
    // Derive expected session key IN-PLACE
    let mut expected = GuardedKey32::zeroed();

    derive_key(
        master,
        Purpose::Recovery,
        INTEGRITY_CONTEXT,
        &mut expected,
    )
    .map_err(|_| IntegrityError::Invalid)?;

    // Constant-time comparison
    if session.borrow().ct_eq(expected.borrow()).into() {
        Ok(())
    } else {
        Err(IntegrityError::Invalid)
    }
}

/// Integrity verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityError {
    Invalid,
}