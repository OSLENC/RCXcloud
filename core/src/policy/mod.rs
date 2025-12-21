

//! Policy engine module.
//!
//! This module defines:
//! - Capability declarations (what a device/function is allowed to do)
//! - Enforcement logic (hard runtime checks, including kill semantics)
//!
//! SECURITY MODEL:
//! - Capabilities are declarative and static
//! - Enforcement is runtime, state-aware, and irreversible on violation
//! - No policy logic is allowed outside this module
//!
//! ARCHITECTURAL RULES:
//! - Application layer may query capabilities but never bypass enforcement
//! - Secure core exclusively owns enforcement decisions
//! - Kill enforcement must never return control to the caller

pub mod capability;
pub mod enforcement;

// Re-export the public policy surface explicitly.
// This makes intent clear and avoids wildcard exports.
pub use capability::{
    Capability,
    CapabilitySet,
};

pub use enforcement::{
    EnforcementEngine,
    EnforcementError,
};