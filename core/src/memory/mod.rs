//! Secure memory management.
//!
//! TRUST LEVEL: Secure Core

#![deny(clippy::derive_debug)]

pub mod guard;
pub mod zeroize;

// ✅ FIX: Re-export the alias we just added
pub use guard::{GuardedBox, GuardedKey32};

// Internal exports (unused import warnings in lib.rs are fine/ignored)
#[allow(unused_imports)]
pub(crate) use zeroize::{wipe_bytes, wipe_vec, Secret};
