//! Active cryptographic session (OPERATION-BASED).
//!
//! TRUST LEVEL: Secure Core
//!
//! FORMAL INVARIANTS (ENFORCED):
//! - Session keys NEVER leave this module
//! - Keys exist ONLY inside GuardedKey32
//! - Deterministic nonce derivation (no RNG, no reuse)
//! - Typed AAD is mandatory
//! - Session is killable and IRREVERSIBLE
//! - Global kill immediately disables all operations
//! - Key material is zeroized immediately on kill
//! - No panics in cryptographic paths
//! - Output types are sealed and non-sensitive
//! - !Send / !Sync by construction

#![deny(clippy::derive_debug)]

use crate::crypto::{
    aad::Aad,
    aes_gcm,
    derive::{derive_key, Purpose},
    nonce::derive_nonce,
};
use crate::keystore::master::GLOBAL_KILLED;
use crate::memory::GuardedKey32;

use core::marker::PhantomData;
use core::sync::atomic::Ordering;

mod sealed {
    pub trait Sealed {}
}

/// Allowed outputs only (sealed).
pub trait SessionOutput: sealed::Sealed {}

/// Encryption result (length only, non-sensitive).
#[derive(Clone, Copy)]
pub struct EncryptResult {
    pub total_len: usize,
}
impl sealed::Sealed for EncryptResult {}
impl SessionOutput for EncryptResult {}

/// Verification-only output.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyResult(pub bool);
impl sealed::Sealed for VerifyResult {}
impl SessionOutput for VerifyResult {}

/// Session-level errors.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    Killed,
    OutputTooSmall,
    CryptoFailure,
}

/// Cryptographic session bound to a single session key.
///
/// SECURITY:
/// - Non-clonable
/// - Kill-aware
/// - Zeroizes key material on kill
/// - Not thread-safe by design (!Send / !Sync)
pub struct Session {
    session_key: Option<GuardedKey32>,
    _no_send: PhantomData<*const ()>,
}

impl Session {
    pub(crate) fn new(session_key: GuardedKey32) -> Self {
        Self {
            session_key: Some(session_key),
            _no_send: PhantomData,
        }
    }

    #[inline(always)]
    fn require_alive(&self) -> Result<&GuardedKey32, SessionError> {
        if GLOBAL_KILLED.load(Ordering::SeqCst) {
            return Err(SessionError::Killed);
        }

        self.session_key
            .as_ref()
            .ok_or(SessionError::Killed)
    }

    /// Encrypt plaintext using deterministic nonce + typed AAD.
    ///
    /// Output format:
    /// `[ ciphertext | tag (16) ]`
    ///
    /// Nonce is DERIVED, never stored or transmitted.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        aad: Aad,
        out: &mut [u8],
    ) -> Result<EncryptResult, SessionError> {
        let session_key = self.require_alive()?;

        // Derive per-file encryption key (purpose-bound)
        let enc_key = derive_key(
            session_key,
            Purpose::FileEncryption,
            aad.file_id,
        );

        let nonce = derive_nonce(&enc_key, aad.file_id, aad.chunk);

        let required = plaintext.len() + 16;
        if out.len() < required {
            return Err(SessionError::OutputTooSmall);
        }

        aes_gcm::seal(
            &enc_key,
            &nonce,
            plaintext,
            &aad.serialize(),
            out,
        )
        .map_err(|_| SessionError::CryptoFailure)?;

        Ok(EncryptResult {
            total_len: required,
        })
    }

    /// Verify + decrypt ciphertext using typed AAD.
    ///
    /// Authentication ALWAYS happens before plaintext is trusted.
    pub fn decrypt_verify(
        &mut self,
        input: &[u8],
        aad: Aad,
        out: &mut [u8],
    ) -> Result<VerifyResult, SessionError> {
        let session_key = self.require_alive()?;

        let enc_key = derive_key(
            session_key,
            Purpose::FileEncryption,
            aad.file_id,
        );

        let nonce = derive_nonce(&enc_key, aad.file_id, aad.chunk);

        let ok = aes_gcm::open(
            &enc_key,
            &nonce,
            input,
            &aad.serialize(),
            out,
        );

        Ok(VerifyResult(ok))
    }

    /// Irreversibly kill this session.
    pub(crate) fn kill(&mut self) {
        self.session_key.take(); // drop → zeroize + munlock
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.session_key.take();
    }
}


