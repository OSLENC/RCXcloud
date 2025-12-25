//! Device identity subsystem (Secure Core).
//!
//! TRUST LEVEL: Secure Core
//!
//! PURPOSE:
//! - Define stable device identity
//! - Provide deterministic fingerprint
//! - Persist irreversible kill state
//!
//! NON-GOALS:
//! - No cryptography
//! - No secrets
//! - No cloud communication
//! - No policy decisions
//!
//! This module is a ROOT dependency for:
//! - kill
//! - recovery
//! - policy
//! - pairing

#![deny(clippy::derive_debug)]

pub mod fingerprint;
pub mod registry;

/* ───────────── CURATED EXPORTS ───────────── */

// Fingerprint (stateless, deterministic)
pub use fingerprint::DeviceFingerprint;

// Registry (stateful, persistent)
pub use registry::{DeviceRegistry, RegistryError};
