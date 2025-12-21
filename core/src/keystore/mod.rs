//! Secure keystore — SINGLE AUTHORITY.
//!
//! FORMAL INVARIANTS (ENFORCED):
//! - Exactly one active session at a time
//! - Session keys never escape GuardedKey32
//! - Remote kill is PROCESS-LIFETIME irreversible
//! - No unlock or use possible after kill
//! - Mutex poisoning FAILS CLOSED (permanent kill)
//! - No panics propagate secrets

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
    Killed,
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
    /// - Mutex poisoning permanently kills keystore
    /// - Authority is consumed exactly once
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
            State::Active(_) => Err(KeyStoreError::Locked),
            State::Killed => Err(KeyStoreError::Killed),
        }
    }

    /// Execute a cryptographic operation within the active session.
    ///
    /// SECURITY:
    /// - Global kill is checked first
    /// - Mutex poisoning permanently kills keystore
    /// - Session enforces its own kill semantics
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
            State::Killed => Err(KeyStoreError::Killed),
        }
    }

    /// Local lock (user-initiated).
    ///
    /// SECURITY:
    /// - Allowed ONLY from Active state
    /// - NO EFFECT after kill
    /// - Mutex poisoning escalates to global kill
    pub fn lock(&self) {
        match self.state.lock() {
            Ok(mut g) => {
                if matches!(*g, State::Active(_)) {
                    *g = State::Locked;
                }
            }
            Err(_) => {
                // Any poisoning = permanent compromise
                GLOBAL_KILLED.store(true, Ordering::SeqCst);
            }
        }
    }

    /// 🔥 IRREVERSIBLE CLOUD KILL 🔥
    ///
    /// SECURITY:
    /// - Cryptographically verified
    /// - Immediately kills active session
    /// - Process-lifetime irreversible
    pub fn apply_remote_kill(&self, kill_blob: &[u8]) {
        if !crate::kill::verify_kill_blob(kill_blob) {
            return;
        }

        GLOBAL_KILLED.store(true, Ordering::SeqCst);

        if let Ok(mut g) = self.state.lock() {
            if let State::Active(ref mut s) = *g {
                s.kill();
            }
            *g = State::Killed;
        }
    }
}