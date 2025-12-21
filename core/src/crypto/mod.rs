
//! Phase 2: Stateless cryptography primitives.
//!
//! NO key storage
//! NO lifecycle
//! NO state
//!
//! Misuse-resistant by construction.

#![deny(clippy::derive_debug)]

pub mod aes_gcm;
pub mod nonce;
pub mod aad;
pub mod kdf_argon2;
pub mod kem;
pub mod derive;

mod sealed {
    pub trait Sealed {}
}

/// Sealed encryption output.
/// Ciphertext format: [nonce | ciphertext | tag]
///
/// NOTE:
/// Ciphertext is NOT secret and MUST NOT be zeroized.
#[must_use]
pub struct EncryptOutput {
    inner: Vec<u8>,
    // Prevent Clone / Copy to avoid accidental duplication
    _no_clone: core::marker::PhantomData<core::cell::Cell<()>>,
}

impl EncryptOutput {
    pub(crate) fn new(buf: Vec<u8>) -> Self {
        Self {
            inner: buf,
            _no_clone: core::marker::PhantomData,
        }
    }

    pub fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl sealed::Sealed for EncryptOutput {}

impl core::fmt::Debug for EncryptOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("<EncryptOutput>")
    }
}

/// Sealed decryption result (length only)
#[must_use]
pub struct DecryptOutput {
    len: usize,
}

impl DecryptOutput {
    pub(crate) fn new(len: usize) -> Self {
        Self { len }
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl sealed::Sealed for DecryptOutput {}

impl core::fmt::Debug for DecryptOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "<DecryptOutput len={}>", self.len)
    }
}

/* ───────────── EXPORT POLICY ───────────── */

// ❌ Raw encryption primitives are NOT public
// They may only be used by higher-level secure modules (session, file pipeline)
pub(crate) use aes_gcm::{encrypt, decrypt};

// Public error types are safe
pub use aes_gcm::{EncryptError, DecryptError};

// KDF primitives
pub use kdf_argon2::{Params, KdfError};

// Key hierarchy & derivation
pub use derive::{derive_key, Purpose};

// KEM primitives (backup / pairing)
pub use kem::{
    csrng,
    decapsulate,
    encapsulate,
    Encapsulation,
    KEMError,
    CsrngError,
};

