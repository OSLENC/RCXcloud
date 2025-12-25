//! Secure Core Bridge API (LANGUAGE-AGNOSTIC).
//!
//! TRUST LEVEL: Secure Core
//!
//! SECURITY MODEL:
//! - Thin facade only
//! - Kill-aware
//! - Fail-closed
//!
//! ❄️ SUBJECT TO SECURE_CORE_API_FREEZE ❄️

#![allow(unsafe_code)] // Required for Send/Sync impls

use core::marker::PhantomData;
use core::sync::atomic::Ordering;
use zeroize::Zeroizing;

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

/* ───────────── PUBLIC ERROR MODEL ───────────── */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreError {
    Locked,
    Killed,
    InvalidInput,
    CryptoFailure,
    IntegrityFailure,
    Denied,
}

/* ───────────── CORE HANDLE ───────────── */

pub struct Core {
    keystore: KeyStore,
    _no_send_sync: PhantomData<*const ()>,
}

// Manual safety guarantees for FFI
unsafe impl Send for Core {}
unsafe impl Sync for Core {}

impl Core {
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

    pub fn unlock_with_phrase(
        &self,
        phrase: Vec<u8>,
    ) -> Result<(), CoreError> {
        self.require_alive()?;
        let phrase = Zeroizing::new(phrase);
        let auth = recover_from_phrase(phrase, &RecoveryConfig::default())
            .map_err(|_| CoreError::IntegrityFailure)?;
        self.keystore.unlock(auth).map_err(map_keystore_error)
    }

    pub fn lock(&self) {
        self.keystore.lock();
    }

    pub fn is_killed(&self) -> bool {
        GLOBAL_KILLED.load(Ordering::SeqCst)
    }

    /* ───────────── FILE CRYPTO ───────────── */

    pub fn encrypt_chunk(
        &self,
        file_id: u64,
        cloud_id: u16,
        chunk: u32,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<EncryptResult, CoreError> {
        self.require_alive()?;

        self.keystore
            .with_session(|session| {
                session.encrypt_chunk(
                    file_id,
                    cloud_id,
                    chunk,
                    plaintext,
                    out
                )
            })
            .map_err(map_keystore_error)
    }

    pub fn decrypt_chunk(
        &self,
        file_id: u64,
        cloud_id: u16,
        chunk: u32,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<VerifyResult, CoreError> {
        self.require_alive()?;

        self.keystore
            .with_session(|session| {
                session.decrypt_chunk(
                    file_id,
                    cloud_id,
                    chunk,
                    ciphertext,
                    out
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
