//! Phase 2: Stateless cryptography primitives.
//!
//! TRUST LEVEL: Secure Core

#![deny(clippy::derive_debug)]

pub mod aad;
pub mod nonce;
pub mod aes_gcm;
pub mod derive;
pub mod kdf_argon2;

#[cfg(feature = "kem")]
pub mod kem;

/* ───────────── EXPORT POLICY ───────────── */

// Only export what is actually used by other modules to avoid warnings
pub use aad::Aad;
pub use nonce::derive_nonce;
pub use derive::{derive_key, Purpose};

#[cfg(feature = "kem")]
pub use kem::{
    csrng,
    encapsulate,
    decapsulate,
    Encapsulation,
    KEMError,
    CsrngError,
};
