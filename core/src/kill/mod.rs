//! Irreversible kill subsystem (Secure Core).
//!
//! TRUST LEVEL: Secure Core
//!
//! This module implements:
//! - Polymorphic kill verification
//! - Replay protection
//! - Terminal execution (no return)
//!
//! POLICY BOUNDARY:
//! - Policy MAY import this module
//! - Executor internals MUST NOT be exposed

#![deny(clippy::derive_debug)]

mod strategy;
mod replay;
mod executor;
mod protocol;

/* ───────────── CURATED EXPORTS ───────────── */

// Kill protocol (shared AAD definition)
pub(crate) use protocol::build_kill_aad;

// Target-side API
pub use strategy::{verify_kill_blob, KillDecision};
pub use executor::{execute_kill, KillError};

// Admin-only generator (MUST NOT ship to targets)
#[cfg(feature = "kill-admin")]
mod generate;

#[cfg(feature = "kill-admin")]
pub(crate) use generate::generate_kill_blob;