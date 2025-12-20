//! RCXCloud Secure Core
//!
//! Cryptographic trust anchor.
//! No UI. No network. No plaintext persistence.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod keystore;
pub mod integrity;
pub mod policy;
pub mod memory;
pub mod media;
pub mod device;
pub mod kill;
pub mod bridge;
