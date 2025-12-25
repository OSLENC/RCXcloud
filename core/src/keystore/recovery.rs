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
            memory_kib: 65536, // 64 MiB
        }
    }
}

/// A proof of authority derived from a recovery phrase.
///
/// This struct wraps the derived root key before it is
/// loaded into the MasterKeyStore.
pub struct RecoveryAuth {
    pub(crate) key: GuardedKey32,
}

pub fn recover_from_phrase(
    phrase: Zeroizing<Vec<u8>>,
    _config: &RecoveryConfig,
) -> Result<RecoveryAuth, ()> {
    // In a real implementation, this would run Argon2id.
    // For this build pass, we assume the phrase IS the key (if 32 bytes)
    // or we hash it. To keep dependencies minimal for now:
    
    // Placeholder logic: Hash phrase to 32 bytes to get root key
    // Real logic would use crate::crypto::kdf_argon2
    
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&*phrase);
    let result = hasher.finalize();
    
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&result);
    
    Ok(RecoveryAuth {
        key: GuardedKey32::new(key_bytes),
    })
}
