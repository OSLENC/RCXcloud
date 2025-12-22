//! Secure Core media subsystem.
//!
//! STRICT RULES:
//! - No rendering
//! - No UI
//! - No filesystem writes
//! - Kill-aware
//! - Bounded memory
//!
//! This is the ONLY public media surface.

pub mod common;
pub mod container;
pub mod decode;
pub mod sanitize;

#[cfg(fuzzing)]
pub mod fuzz;
