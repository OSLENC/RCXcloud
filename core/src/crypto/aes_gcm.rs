//! AES-256-GCM wrapper (FIPS 197 / NIST SP 800-38D).
//!
//! TRUST LEVEL: Secure Core
//!
//! INVARIANTS:
//! - 96-bit Nonce (Fixed)
//! - 128-bit Tag (Fixed)
//! - Key is GuardedKey32 (Heap Protected)

use crate::memory::GuardedKey32;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce, Tag,
};

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

/// Encrypt data in-place or into a buffer.
///
/// Returns the length of the ciphertext (plaintext.len() + 16).
pub fn encrypt(
    key: &GuardedKey32,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
    dst: &mut [u8],
) -> Result<usize, ()> {
    let cipher = Aes256Gcm::new(key.borrow().into());
    let nonce = Nonce::from_slice(nonce);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    // We use the 'encrypt' method which allocates a Vec by default in some versions,
    // but here we want to write to 'dst'. 
    // Optimization: For strict memory control, we verify size first.
    if dst.len() < plaintext.len() + TAG_LEN {
        return Err(());
    }

    let ct = cipher.encrypt(nonce, payload).map_err(|_| ())?;
    
    // Copy result to destination (since Aead trait returns Vec by default)
    // In a zero-alloc env, we would use AeadInPlace, but for now this is safe.
    dst[..ct.len()].copy_from_slice(&ct);
    
    Ok(ct.len())
}

/// Decrypt data.
///
/// Returns the length of the plaintext (ciphertext.len() - 16).
pub fn decrypt(
    key: &GuardedKey32,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
    dst: &mut [u8],
) -> Result<usize, ()> {
    let cipher = Aes256Gcm::new(key.borrow().into());
    let nonce = Nonce::from_slice(nonce);

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    let pt = cipher.decrypt(nonce, payload).map_err(|_| ())?;

    if dst.len() < pt.len() {
        return Err(());
    }

    dst[..pt.len()].copy_from_slice(&pt);

    Ok(pt.len())
}

// Re-export seal/open for legacy session code if needed, 
// but the wrappers above are cleaner.
pub fn seal(
    key: &GuardedKey32,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
    dst: &mut [u8],
) -> Result<(), ()> {
    encrypt(key, nonce, plaintext, aad, dst).map(|_| ())
}

pub fn open(
    key: &GuardedKey32,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
    dst: &mut [u8],
) -> bool {
    decrypt(key, nonce, ciphertext, aad, dst).is_ok()
}
