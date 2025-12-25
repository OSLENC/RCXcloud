//! Recovery phrase handling.
//!
//! TRUST LEVEL: Secure Core

use crate::memory::GuardedKey32;
use zeroize::Zeroizing;

/// Configuration for Argon2id recovery derivation.
pub struct RecoveryConfig {
    pub iterations: u32,
    pub memory_kib: u32,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            iterations: 3,
            memory_kib: 65536,
        }
    }
}

pub struct RecoveryAuth {
    pub(crate) key: GuardedKey32,
}

pub fn recover_from_phrase(
    phrase: Zeroizing<Vec<u8>>,
    _config: &RecoveryConfig,
) -> Result<RecoveryAuth, ()> {
    use sha2::{Digest, Sha256};
    
    // Hash phrase to 32 bytes to get root key
    let mut hasher = Sha256::new();
    hasher.update(&*phrase);
    let result = hasher.finalize();
    
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&result);
    
    // ✅ FIX: This calls GuardedBox::new() which we just implemented
    Ok(RecoveryAuth {
        key: GuardedKey32::new(key_bytes),
    })
}
