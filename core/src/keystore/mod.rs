//! Keystore state machine.
//!
//! TRUST LEVEL: Secure Core

#![deny(clippy::derive_debug)]

pub mod master;
pub mod recovery;
pub mod session;

use crate::memory::GuardedKey32;
use master::{MasterKeyStore, GLOBAL_KILLED};
use recovery::RecoveryAuth;
use session::{Session, SessionError}; // ✅ FIX: Removed SessionOutput
use core::sync::atomic::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStoreError {
    Locked,
    Killed,
    Poisoned,
    AlreadyUnlocked,
    Session(SessionError),
}

/// The central key management authority.
pub struct KeyStore {
    inner: MasterKeyStore,
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            inner: MasterKeyStore::new(),
        }
    }

    pub fn unlock(&self, auth: RecoveryAuth) -> Result<(), KeyStoreError> {
        if GLOBAL_KILLED.load(Ordering::SeqCst) {
            return Err(KeyStoreError::Killed);
        }
        self.inner.unlock(auth).map_err(|_| KeyStoreError::Locked)
    }

    pub fn lock(&self) {
        self.inner.lock();
    }

    pub fn with_session<F, R>(&self, f: F) -> Result<R, KeyStoreError>
    where
        F: FnOnce(&Session) -> Result<R, SessionError>,
    {
        if GLOBAL_KILLED.load(Ordering::SeqCst) {
            return Err(KeyStoreError::Killed);
        }

        // 1. Get Root Key (fails if locked)
        let root_key = self.inner.get_root_key().ok_or(KeyStoreError::Locked)?;

        // 2. Create Ephemeral Session
        // We clone the guarded key (which is cheap, just a pointer copy of the guard)
        // or re-wrap the raw bytes. MasterKeyStore::get_root_key returns GuardedKey32.
        let session = Session::new(root_key);

        // 3. Execute Closure
        let result = f(&session);

        // 4. Cleanup happens on Drop of Session
        result.map_err(KeyStoreError::Session)
    }
    
    // Helper to wipe keys (used by kill executor)
    pub fn wipe(&self) {
        // MasterKeyStore doesn't expose explicit wipe, but lock() 
        // drops the internal key, effectively wiping it.
        self.inner.lock();
    }
}
