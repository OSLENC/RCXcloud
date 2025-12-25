//! Secure logging subsystem (secure core).
//!
//! TRUST LEVEL: Secure Core (PASSIVE STORAGE)
//!
//! SECURITY INVARIANTS:
//! - Append-only
//! - Fail-closed
//! - Crash-safe (atomic checks)


#![deny(clippy::derive_debug)]

pub mod encrypted;
pub mod events;


