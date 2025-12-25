//! Master Key Management (Secure Core).

#![deny(clippy::derive_debug)]

use crate::memory::GuardedKey32;

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

/* ───────────── GLOBAL KILL FUSE ───────────── */

pub(crate) static GLOBAL_KILLED: AtomicBool = AtomicBool::new(false);

#[inline(always)]
pub(crate) fn is_globally_killed() -> bool {
    GLOBAL_KILLED.load(Ordering::SeqCst)
}

/* ───────────── ERRORS ───────────── */

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum KeystoreError {
    Locked,
    Wiped,
    Poisoned,
    AlreadyUnlocked,
}

/* ───────────── INTERNAL STATE ───────────── */

enum KeyState {
    Locked,
    Unlocked(GuardedKey32),
    Wiped,
}

/* ───────────── MASTER KEY STORE ───────────── */

pub struct MasterKeyStore {
    state: Mutex<KeyState>,
}

impl MasterKeyStore {
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(KeyState::Locked),
        }
    }

    pub fn unlock(&self, key: GuardedKey32) -> Result<(), KeystoreError> {
        if is_globally_killed() {
            drop(key);
            return Err(KeystoreError::Wiped);
        }

        let mut guard = self.acquire_lock()?;

        if is_globally_killed() {
            drop(key);
            return Err(KeystoreError::Wiped);
        }

        match *guard {
            KeyState::Locked => {
                *guard = KeyState::Unlocked(key);
                Ok(())
            }
            _ => {
                drop(key);
                Err(KeystoreError::AlreadyUnlocked)
            }
        }
    }

    pub fn lock(&self) -> Result<(), KeystoreError> {
        let mut guard = self.acquire_lock()?;

        if is_globally_killed() {
            *guard = KeyState::Wiped;
            return Err(KeystoreError::Wiped);
        }

        *guard = KeyState::Locked;
        Ok(())
    }

    /// 🔥 IRREVERSIBLE TERMINAL KILL 🔥
    ///
    /// Caller MUST have already verified kill authorization.
    pub fn apply_verified_kill(&self) {
        GLOBAL_KILLED.store(true, Ordering::SeqCst);

        if let Ok(mut guard) = self.state.lock() {
            *guard = KeyState::Wiped;
        }
    }

    pub fn with_key<F, R>(&self, f: F) -> Result<R, KeystoreError>
    where
        F: FnOnce(&[u8; 32]) -> R,
    {
        if is_globally_killed() {
            return Err(KeystoreError::Wiped);
        }

        let guard = self.acquire_lock()?;

        match &*guard {
            KeyState::Unlocked(key) => Ok(f(key.borrow())),
            KeyState::Locked => Err(KeystoreError::Locked),
            KeyState::Wiped => Err(KeystoreError::Wiped),
        }
    }

    fn acquire_lock(&self) -> Result<MutexGuard<'_, KeyState>, KeystoreError> {
        self.state.lock().map_err(|_| {
            GLOBAL_KILLED.store(true, Ordering::SeqCst);
            KeystoreError::Poisoned
        })
    }
}