//! Policy engine module.
//!
//! TRUST LEVEL: Secure Core

pub mod capability;
pub mod enforcement;

/* ───────────── CURATED EXPORTS ───────────── */

// Capabilities (static concepts)
pub use capability::Capability;

// Enforcement (runtime logic)
pub use enforcement::{
    CapabilitySet,
    PolicyEnforcer,
    Operation,
};