//! Recovery → AUTHORITY, NOT KEYS.
//!
//! TRUST LEVEL: Secure Core
//!
//! PURPOSE:
//! - Derive guarded session authority from user recovery material
//! - Verify cryptographic binding
//!
//! FORMAL INVARIANTS:
//! - Recovery never exposes raw keys
//! - Root material is used ONLY for integrity verification
//! - Session key is guarded
//! - Authority is single-use
//! - No panics in cryptographic paths

#![deny(clippy::derive_debug)]

use crate::crypto::kdf_argon2;
use crate::integrity::verify_key_integrity;
use crate::memory::GuardedKey32;
use zeroize::Zeroizing;

/* ───────────── CONFIG ───────────── */

#[derive(Clone, Copy)]
pub struct RecoveryConfig {
    pub kdf: kdf_argon2::Params,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            kdf: kdf_argon2::Params::default(),
        }
    }
}

/* ───────────── ERRORS ───────────── */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryError {
    InvalidInput,
    KdfFailure,
    IntegrityFailure,
}

/* ───────────── AUTHORITY ───────────── */

/// Single-use recovery authority.
/// Holds ONLY the session key.
pub struct RecoveryAuthority {
    session: GuardedKey32,
}

impl RecoveryAuthority {
    /// Consume the authority and extract the guarded session key.
    ///
    /// SECURITY:
    /// - Single-use by construction
    /// - Session key remains guarded
    pub(crate) fn consume(self) -> GuardedKey32 {
        self.session
    }
}

/* ───────────── ENTRY POINT ───────────── */

/// Recover a session authority from a recovery phrase.
///
/// SECURITY:
/// - Root key NEVER escapes this function
/// - Root is used ONLY for integrity verification
/// - Session key is returned as guarded authority
pub fn recover_from_phrase(
    phrase: Zeroizing<Vec<u8>>,
    cfg: &RecoveryConfig,
) -> Result<RecoveryAuthority, RecoveryError> {
    if phrase.is_empty() {
        return Err(RecoveryError::InvalidInput);
    }

    // Guarded outputs
    let mut root = GuardedKey32::zeroed();
    let mut session = GuardedKey32::zeroed();

    // Deterministic KDF (no RNG)
    kdf_argon2::derive_two_keys(
        &phrase,
        b"rcxcloud-recovery-v1",
        &cfg.kdf,
        &mut root,
        &mut session,
    )
    .map_err(|_| RecoveryError::KdfFailure)?;

    // Cryptographic binding check
    verify_key_integrity(&root, &session)
        .map_err(|_| RecoveryError::IntegrityFailure)?;

    // Root is dropped here; session becomes authority
    Ok(RecoveryAuthority { session })
}


