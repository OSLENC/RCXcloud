#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(warnings)]
#![deny(clippy::all)]
#![deny(unsafe_code)]

//! RCXCloud Secure Core
//!
//! Cryptographic trust anchor.
//! No UI. No network. No plaintext persistence.

#![forbid(unsafe_code)]

pub mod bridge;
pub mod crypto;
pub mod device;
pub mod integrity;
pub mod keystore;
pub mod kill;
pub mod media;
pub mod memory;
pub mod policy;
