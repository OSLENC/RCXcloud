//! Secure Core Bridge API (LANGUAGE-AGNOSTIC).
//!
//! This is the ONLY public interface exposed to:
//! - JNI / Android
//! - C / C++ FFI
//! - WASM / plugin runtimes
//!
//! SECURITY MODEL:
//! - Thin facade only
//! - No crypto primitives exposed
//! - No secret material exposed
//! - Kill-first, fail-closed
//! - Deterministic, synchronous behavior
//!
//! ⚠️ POLICY NOTE:
//! This bridge exposes MECHANISMS (encrypt/decrypt).
//! It does NOT enforce high-level POLICY (e.g. "Can User X upload?").
//! The Application Layer MUST enforce Policy before calling these methods.
//!
//! ❄️ SUBJECT TO SECURE_CORE_API_FREEZE ❄️

use core::marker::PhantomData;
use core::sync::atomic::Ordering;
use zeroize::Zeroizing;

use crate::crypto::file::{
    encrypt_chunk,
    decrypt_chunk,
    FileId,
    CloudId,
};

use crate::keystore::{
    KeyStore,
    KeyStoreError,
};

use crate::keystore::recovery::{
    recover_from_phrase,
    RecoveryConfig,
};

use crate::keystore::session::{
    EncryptResult,
    VerifyResult,
    SessionError,
};

use crate::keystore::master::GLOBAL_KILLED;

/* ─────────────────────────────────────────────
   PUBLIC ERROR MODEL (FROZEN SURFACE)
   ───────────────────────────────────────────── */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreError {
    Locked,
    Killed,
    InvalidInput,
    CryptoFailure,
    IntegrityFailure,
    Denied,
}

/* ─────────────────────────────────────────────
   CORE HANDLE
   ───────────────────────────────────────────── */

/// Secure Core handle.
///
/// Owns exactly ONE keystore.
///
/// SECURITY:
/// - Not clonable
/// - NOT Send / Sync
/// - Kill-aware
pub struct Core {
    keystore: KeyStore,
    // Explicitly forbid Send + Sync across language boundaries
    _no_send_sync: PhantomData<*const ()>,
}

unsafe impl Send for Core {}
unsafe impl Sync for Core {}

impl Core {
    /* ───────────── LIFECYCLE ───────────── */

    pub fn new() -> Self {
        Self {
            keystore: KeyStore::new(),
            _no_send_sync: PhantomData,
        }
    }

    #[inline(always)]
    fn require_alive(&self) -> Result<(), CoreError> {
        if GLOBAL_KILLED.load(Ordering::SeqCst) {
            Err(CoreError::Killed)
        } else {
            Ok(())
        }
    }

    /// Unlock Secure Core using a recovery phrase.
    pub fn unlock_with_phrase(
        &self,
        phrase: Vec<u8>,
    ) -> Result<(), CoreError> {
        self.require_alive()?;

        let phrase = Zeroizing::new(phrase);

        let auth = recover_from_phrase(
            phrase,
            &RecoveryConfig::default(),
        )
        .map_err(|_| CoreError::IntegrityFailure)?;

        self.keystore
            .unlock(auth)
            .map_err(map_keystore_error)
    }

    /// User-initiated local lock.
    pub fn lock(&self) {
        self.keystore.lock();
    }

    /// Check whether Secure Core is killed.
    pub fn is_killed(&self) -> bool {
        GLOBAL_KILLED.load(Ordering::SeqCst)
    }

    /* ───────────── FILE CRYPTO ───────────── */

    /// Encrypt a file chunk.
    pub fn encrypt_chunk(
        &self,
        file_id: FileId,
        cloud_id: CloudId,
        chunk: u32,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<EncryptResult, CoreError> {
        self.require_alive()?;

        self.keystore
            .with_session(|s| {
                encrypt_chunk(
                    s,
                    file_id,
                    cloud_id,
                    chunk,
                    plaintext,
                    out,
                )
            })
            .map_err(map_keystore_error)
    }

    /// Decrypt + verify a file chunk.
    pub fn decrypt_chunk(
        &self,
        file_id: FileId,
        cloud_id: CloudId,
        chunk: u32,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<VerifyResult, CoreError> {
        self.require_alive()?;

        self.keystore
            .with_session(|s| {
                decrypt_chunk(
                    s,
                    file_id,
                    cloud_id,
                    chunk,
                    ciphertext,
                    out,
                )
            })
            .map_err(map_keystore_error)
    }
}

/* ───────────── ERROR MAPPING ───────────── */

#[inline(always)]
fn map_keystore_error(err: KeyStoreError) -> CoreError {
    match err {
        KeyStoreError::Locked => CoreError::Locked,
        KeyStoreError::Killed => CoreError::Killed,
        KeyStoreError::Poisoned => CoreError::Killed,
        KeyStoreError::AlreadyUnlocked => CoreError::Denied,
        KeyStoreError::Session(se) => map_session_error(se),
    }
}

#[inline(always)]
fn map_session_error(err: SessionError) -> CoreError {
    match err {
        SessionError::Killed => CoreError::Killed,
        SessionError::Locked => CoreError::Locked,
        SessionError::InvalidInput => CoreError::InvalidInput,
        SessionError::OutputTooSmall => CoreError::InvalidInput,
        SessionError::CryptoFailure => CoreError::CryptoFailure,
    }
}


