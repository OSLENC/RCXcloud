//! Recovery → AUTHORITY, NOT KEYS.

#![deny(clippy::derive_debug)]

use crate::crypto::kdf_argon2;
use crate::integrity::verify;
use crate::memory::{GuardedBox, GuardedKey32};
use zeroize::Zeroizing;

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

#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryError {
    InvalidInput,
    KdfFailure,
    IntegrityFailure,
}

pub struct RecoveryAuthority {
    session: GuardedKey32,
}

pub fn recover_from_phrase(
    phrase: Zeroizing<Vec<u8>>,
    cfg: &RecoveryConfig,
) -> Result<RecoveryAuthority, RecoveryError> {
    if phrase.is_empty() {
        return Err(RecoveryError::InvalidInput);
    }

    let material = GuardedBox::<[u8; 64]>::init_with(|buf| {
        if kdf_argon2::derive_64_bytes(&phrase, &cfg.kdf, buf).is_err() {
            return;
        }
    });

    let root: &[u8; 32] = material.borrow()[0..32]
        .try_into()
        .map_err(|_| RecoveryError::IntegrityFailure)?;

    let session = GuardedKey32::init_with(|s| {
        s.copy_from_slice(&material.borrow()[32..64]);
    });

    verify::verify_key_integrity(root, session.borrow())
        .map_err(|_| RecoveryError::IntegrityFailure)?;

    Ok(RecoveryAuthority { session })
}

impl RecoveryAuthority {
    pub(crate) fn consume(self) -> GuardedKey32 {
        self.session
    }
}
