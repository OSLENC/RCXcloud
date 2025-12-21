//! Master Key Management (Secure Core).
//!
//! TRUST ANCHOR — DO NOT WEAKEN.

use crate::memory::GuardedKey32;
use crate::kill;
use std::sync::{Mutex, MutexGuard};
use core::sync::atomic::{AtomicBool, Ordering};

/* ───────────── GLOBAL KILL FUSE ───────────── */

pub(crate) static GLOBAL_KILLED: AtomicBool = AtomicBool::new(false);

#[inline(always)]
fn is_killed() -> bool {
    GLOBAL_KILLED.load(Ordering::SeqCst)
}

/* ───────────── ERROR TYPES ───────────── */

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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
        if is_killed() {
            drop(key);
            return Err(KeystoreError::Wiped);
        }

        let mut guard = self.acquire_lock()?;

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
        if is_killed() {
            return Err(KeystoreError::Wiped);
        }

        let mut guard = self.acquire_lock()?;

        match *guard {
            KeyState::Unlocked(_) | KeyState::Locked => {
                *guard = KeyState::Locked;
                Ok(())
            }
            KeyState::Wiped => Err(KeystoreError::Wiped),
        }
    }

    /// 🔥 CLOUD REMOTE KILL — IRREVERSIBLE
    pub fn apply_remote_kill(&self, kill_blob: &[u8]) {
        if kill::verify_kill_blob(kill_blob).is_none() {
            return;
        }

        GLOBAL_KILLED.store(true, Ordering::SeqCst);

        if let Ok(mut guard) = self.state.lock() {
            // Explicit drop of guarded key happens here
            *guard = KeyState::Wiped;
        }
    }

    pub fn with_key<F, R>(&self, f: F) -> Result<R, KeystoreError>
    where
        F: FnOnce(MasterKeyHandle<'_>) -> R,
        R: MasterKeyOutput,
    {
        if is_killed() {
            return Err(KeystoreError::Wiped);
        }

        let guard = self.acquire_lock()?;

        match &*guard {
            KeyState::Unlocked(key) => Ok(f(MasterKeyHandle {
                key: key.borrow(),
            })),
            KeyState::Locked => Err(KeystoreError::Locked),
            KeyState::Wiped => Err(KeystoreError::Wiped),
        }
    }

    fn acquire_lock(&self) -> Result<MutexGuard<'_, KeyState>, KeystoreError> {
        self.state.lock().map_err(|_| KeystoreError::Poisoned)
    }
}

/* ───────────── SEALED HANDLE API ───────────── */

pub struct MasterKeyHandle<'a> {
    key: &'a [u8; 32],
}

impl<'a> MasterKeyHandle<'a> {
    pub fn verify<F>(&self, f: F) -> VerifyResult
    where
        F: FnOnce(&[u8; 32]) -> bool,
    {
        VerifyResult(f(self.key))
    }

    pub fn authenticate<F>(&self, f: F) -> AuthResult
    where
        F: FnOnce(&[u8; 32]) -> bool,
    {
        if f(self.key) {
            AuthResult::Success
        } else {
            AuthResult::Failure
        }
    }
}

/* ───────────── SEALED OUTPUT TYPES ───────────── */

mod sealed {
    pub trait Sealed {}
}

pub trait MasterKeyOutput: sealed::Sealed {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyResult(pub bool);
impl sealed::Sealed for VerifyResult {}
impl MasterKeyOutput for VerifyResult {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResult {
    Success,
    Failure,
}
impl sealed::Sealed for AuthResult {}
impl MasterKeyOutput for AuthResult {}
