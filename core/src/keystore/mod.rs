//! Secure keystore — SINGLE AUTHORITY.

#![deny(clippy::derive_debug)]

pub mod session;
pub mod recovery;

use session::{Session, SessionError, SessionOutput};
use recovery::RecoveryAuthority;

use std::sync::Mutex;
use core::sync::atomic::Ordering;

use crate::keystore::master::GLOBAL_KILLED;

/* ───────────── ERROR TYPES ───────────── */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStoreError {
    Locked,
    AlreadyUnlocked,
    Killed,
    Poisoned,
    Session(SessionError),
}

impl From<SessionError> for KeyStoreError {
    fn from(e: SessionError) -> Self {
        KeyStoreError::Session(e)
    }
}

/* ───────────── INTERNAL STATE ───────────── */

enum State {
    Locked,
    Active(Session),
}

/* ───────────── KEYSTORE ───────────── */

pub struct KeyStore {
    state: Mutex<State>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State::Locked),
        }
    }

    /// Unlock keystore using a recovery authority.
    ///
    /// SECURITY:
    /// - Forbidden after global kill
    /// - Authority is single-use
    /// - Mutex poisoning FAILS CLOSED
    pub fn unlock(&self, auth: RecoveryAuthority) -> Result<(), KeyStoreError> {
        if GLOBAL_KILLED.load(Ordering::SeqCst) {
            return Err(KeyStoreError::Killed);
        }

        let mut g = self.state.lock().map_err(|_| {
            GLOBAL_KILLED.store(true, Ordering::SeqCst);
            KeyStoreError::Poisoned
        })?;

        match *g {
            State::Locked => {
                let session_key = auth.consume();
                *g = State::Active(Session::new(session_key));
                Ok(())
            }
            State::Active(_) => Err(KeyStoreError::AlreadyUnlocked),
        }
    }

    /// Execute a cryptographic operation within the active session.
    pub fn with_session<F, R>(&self, f: F) -> Result<R, KeyStoreError>
    where
        F: FnOnce(&mut Session) -> Result<R, SessionError>,
        R: SessionOutput,
    {
        if GLOBAL_KILLED.load(Ordering::SeqCst) {
            return Err(KeyStoreError::Killed);
        }

        let mut g = self.state.lock().map_err(|_| {
            GLOBAL_KILLED.store(true, Ordering::SeqCst);
            KeyStoreError::Poisoned
        })?;

        match &mut *g {
            State::Active(s) => f(s).map_err(KeyStoreError::from),
            State::Locked => Err(KeyStoreError::Locked),
        }
    }

    /// Local lock (user-initiated).
    ///
    /// SECURITY:
    /// - Explicitly kills active session
    /// - No effect after global kill
    pub fn lock(&self) {
        if GLOBAL_KILLED.load(Ordering::SeqCst) {
            return;
        }

        match self.state.lock() {
            Ok(mut g) => {
                if let State::Active(ref mut s) = *g {
                    s.kill();
                    *g = State::Locked;
                }
            }
            Err(_) => {
                GLOBAL_KILLED.store(true, Ordering::SeqCst);
            }
        }
    }

    /// 🔥 IRREVERSIBLE CLOUD KILL 🔥
    ///
    /// CALLED ONLY AFTER:
    /// - kill blob verification
    /// - replay check
    ///
    /// This function performs **execution only**.
    pub(crate) fn apply_verified_kill(&self) {
        GLOBAL_KILLED.store(true, Ordering::SeqCst);

        if let Ok(mut g) = self.state.lock() {
            if let State::Active(ref mut s) = *g {
                s.kill();
            }
            *g = State::Locked;
        }
    }
}


