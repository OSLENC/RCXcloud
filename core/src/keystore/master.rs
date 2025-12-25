//! Master Key Storage (The "Vault").
//!
//! TRUST LEVEL: Secure Core

use crate::memory::GuardedKey32;
use crate::keystore::recovery::RecoveryAuth;
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

/// Global kill switch flag.
/// If true, ALL crypto operations fail immediately.
pub static GLOBAL_KILLED: AtomicBool = AtomicBool::new(false);

pub struct MasterKeyStore {
    root_key: RwLock<Option<GuardedKey32>>,
}

impl MasterKeyStore {
    pub fn new() -> Self {
        Self {
            root_key: RwLock::new(None),
        }
    }

    pub fn unlock(&self, auth: RecoveryAuth) -> Result<(), ()> {
        let mut lock = self.root_key.write().map_err(|_| ())?;
        if lock.is_some() {
            return Err(()); // Already unlocked
        }
        *lock = Some(auth.key);
        Ok(())
    }

    pub fn lock(&self) {
        if let Ok(mut lock) = self.root_key.write() {
            *lock = None;
        }
    }

    /// Retrieve a handle to the root key (if unlocked).
    /// Used by Session to derive ephemeral keys.
    pub fn get_root_key(&self) -> Option<GuardedKey32> {
        let lock = self.root_key.read().ok()?;
        // Clone the GuardedKey32 (allocates new protected memory)
        lock.as_ref().cloned()
    }
}
