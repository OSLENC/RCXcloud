
//! Integrity primitives (Secure Core).
//!
//! TRUST LEVEL: Secure Core
//!
//! PURPOSE:
//! - Non-secret hashing
//! - Cryptographic key integrity verification
//!
//! This module defines what it means for data and keys
//! to be *valid* before higher-level authorization or recovery.

#![deny(clippy::derive_debug)]

pub mod hash;
pub mod verify;

pub use hash::{hash_sha256, HashOutput};
pub use verify::{verify_key_integrity, IntegrityError};