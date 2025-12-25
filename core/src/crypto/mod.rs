//! Phase 2: Stateless cryptography primitives.
//!
//! TRUST LEVEL: Secure Core

#![deny(clippy::derive_debug)]

pub mod aad;
pub mod nonce;
pub mod aes_gcm;
pub mod derive;
pub mod kdf_argon2;

// ✅ FIX: Gate the module declaration itself
#[cfg(feature = "kem")]
pub mod kem;

/* ───────────── EXPORT POLICY ───────────── */

pub use aad::{Aad, AAD_VERSION_V1};
pub use nonce::{derive_nonce, NONCE_LEN};
pub use derive::{derive_key, Purpose};
pub use kdf_argon2::{Params, KdfError};

// ✅ FIX: Gate the re-exports
#[cfg(feature = "kem")]
pub use kem::{
    csrng,
    encapsulate,
    decapsulate,
    Encapsulation,
    KEMError,
    CsrngError,
};
