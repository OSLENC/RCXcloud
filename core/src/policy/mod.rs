
//! Policy engine module.
//!
//! TRUST LEVEL: Secure Core
//!
//! Defines:
//! - Capabilities (what is allowed)
//! - Enforcement (when it is allowed)

pub mod capability;
pub mod enforcement;

/* ───────────── CURATED EXPORTS ───────────── */

pub use capability::{
    Capability,
    CapabilitySet,
};

pub use enforcement::{
    PolicyEnforcer,
    Operation,
};