//! Irreversible kill subsystem (Secure Core).
//!
//! TRUST LEVEL: Secure Core
//!
//! This module implements:
//! - Polymorphic kill verification
//! - Replay protection
//! - Terminal execution (no return)
//!
//! Any successful kill permanently disables the device.

#![deny(clippy::derive_debug)]

mod strategy;
mod replay;
mod executor;

// Admin-only kill generation (NOT exposed via bridge / plugins)
#[cfg(feature = "admin")]
mod generate;

/* ───────────── TARGET-SIDE PUBLIC API ───────────── */

pub use strategy::{verify_kill_blob, KillDecision};
pub use executor::{execute_kill, KillError};

/* ───────────── ADMIN-ONLY INTERNAL API ───────────── */

#[cfg(feature = "admin")]
pub(crate) use generate::generate_kill_blob;


