//! Active cryptographic session (OPERATION-BASED).
//!
//! TRUST LEVEL: Secure Core
//!
//! SECURITY INVARIANTS:
//! - Session key is heap-locked (GuardedKey32)
//! - Forbidden after global kill
//! - Deterministic derivation only
//! - AEAD verify-then-decrypt
//! - Fail-closed
//! - No raw key exposure
//! - No Clone / Copy / Debug

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

/* ───────────── SEALED OUTPUT TRAITS ───────────── */

mod sealed {
    pub trait Sealed {}
}

pub trait SessionOutput: sealed::Sealed {}

/* ───────────── OUTPUT TYPES ───────────── */

#[derive(Clone, Copy)]
pub struct EncryptResult {
    pub total_len: usize,
}
impl sealed::Sealed for EncryptResult {}
impl SessionOutput for EncryptResult {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyResult(pub bool);
impl sealed::Sealed for VerifyResult {}
impl SessionOutput for VerifyResult {}

/* ───────────── ERRORS ───────────── */

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    Killed,
    Locked,
    InvalidInput,
    OutputTooSmall,
    CryptoFailure,
}

/* ───────────── SESSION TYPE ───────────── */

pub struct Session {
    session_key: Option<GuardedKey32>,
    _no_send_sync: PhantomData<*const ()>,
}

impl Session {
    /* ───────────── CONSTRUCTION ───────────── */

    pub(crate) fn new(session_key: GuardedKey32) -> Self {
        Self {
            session_key: Some(session_key),
            _no_send_sync: PhantomData,
        }
    }

    /* ───────────── INTERNAL GUARDS ───────────── */

    #[inline(always)]
    fn require_alive(&self) -> Result<&GuardedKey32, SessionError> {
        if GLOBAL_KILLED.load(Ordering::SeqCst) {
            return Err(SessionError::Killed);
        }

        self.session_key
            .as_ref()
            .ok_or(SessionError::Locked)
    }

    /* ───────────── ENCRYPT ───────────── */

    /// Encrypt plaintext using derived file key.
    ///
    /// Output format:
    /// `[ ciphertext | tag ]`
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        aad: Aad,
        out: &mut [u8],
    ) -> Result<EncryptResult, SessionError> {
        let session_key = self.require_alive()?;

        let required = plaintext.len() + aes_gcm::TAG_LEN;
        if out.len() != required {
            out.fill(0);
            return Err(SessionError::OutputTooSmall);
        }

        let mut enc_key = GuardedKey32::zeroed();

        derive_key(
            session_key,
            Purpose::FileEncryption,
            aad.file_id(),
            &mut enc_key,
        )
        .map_err(|_| {
            out.fill(0);
            SessionError::CryptoFailure
        })?;

        if GLOBAL_KILLED.load(Ordering::SeqCst) {
            out.fill(0);
            return Err(SessionError::Killed);
        }

        let nonce = derive_nonce(&enc_key, aad.file_id(), aad.chunk());

        aes_gcm::seal(
            &enc_key,
            &nonce,
            plaintext,
            &aad.serialize(),
            out,
        )
        .map_err(|_| {
            out.fill(0);
            SessionError::CryptoFailure
        })?;

        Ok(EncryptResult {
            total_len: required,
        })
    }

    /* ───────────── DECRYPT + VERIFY ───────────── */

    /// Authenticate and decrypt ciphertext.
    ///
    /// Returns `VerifyResult(false)` on authentication failure.
    pub fn decrypt_verify(
        &mut self,
        input: &[u8],
        aad: Aad,
        out: &mut [u8],
    ) -> Result<VerifyResult, SessionError> {
        let session_key = self.require_alive()?;

        if input.len() < aes_gcm::TAG_LEN {
            out.fill(0);
            return Err(SessionError::InvalidInput);
        }

        let ct_len = input.len() - aes_gcm::TAG_LEN;
        if out.len() != ct_len {
            out.fill(0);
            return Err(SessionError::OutputTooSmall);
        }

        let mut enc_key = GuardedKey32::zeroed();

        derive_key(
            session_key,
            Purpose::FileEncryption,
            aad.file_id(),
            &mut enc_key,
        )
        .map_err(|_| {
            out.fill(0);
            SessionError::CryptoFailure
        })?;

        if GLOBAL_KILLED.load(Ordering::SeqCst) {
            out.fill(0);
            return Err(SessionError::Killed);
        }

        let nonce = derive_nonce(&enc_key, aad.file_id(), aad.chunk());

        let ok = aes_gcm::open(
            &enc_key,
            &nonce,
            input,
            &aad.serialize(),
            out,
        );

        if !ok {
            out.fill(0);
        }

        Ok(VerifyResult(ok))
    }

    /* ───────────── TERMINATION ───────────── */

    /// Kill this session explicitly.
    ///
    /// SECURITY:
    /// - Zeroizes and drops session key
    pub(crate) fn kill(&mut self) {
        self.session_key.take();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.session_key.take();
    }
}