//! Master Key Storage (The "Vault").
//!
//! TRUST LEVEL: Secure Core

use crate::memory::GuardedKey32;
use crate::keystore::recovery::RecoveryAuth;
use core::sync::atomic::AtomicBool; // Removed Ordering unused import
use std::sync::RwLock;

/// Global kill switch flag.
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
            return Err(());
        }
        *lock = Some(auth.key);
        Ok(())
    }

    pub fn lock(&self) {
        if let Ok(mut lock) = self.root_key.write() {
            *lock = None;
        }
    }

    pub fn get_root_key(&self) -> Option<GuardedKey32> {
        let lock = self.root_key.read().ok()?;
        // ✅ FIX: This works now because GuardedBox implements Clone
        lock.as_ref().cloned()
    }
}
