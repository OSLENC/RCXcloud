
//! Key integrity verification (Secure Core).
//!
//! PURPOSE:
//! Verify that a session key is correctly derived from a master key.
//!
//! SECURITY INVARIANTS:
//! - No stack-resident secrets
//! - GuardedKey32 ONLY
//! - Deterministic derivation
//! - Constant-time comparison
//! - Fail closed

use crate::crypto::derive::{derive_key, Purpose};
use crate::memory::GuardedKey32;
use subtle::ConstantTimeEq;

pub fn verify_key_integrity(
    master: &GuardedKey32,
    session: &GuardedKey32,
    context: u128,
) -> Result<(), IntegrityError> {
    let expected = derive_key(master, Purpose::FileEncryption, context);

    if session.borrow().ct_eq(expected.borrow()).into() {
        Ok(())
    } else {
        Err(IntegrityError::Invalid)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityError {
    Invalid,
}
