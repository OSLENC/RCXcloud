//! Secure Core bridge boundary.
//!
//! This module defines the ONLY public integration surface for:
//! - JNI (Android)
//! - FFI (C / Swift / Python / WASM)
//! - Plugins
//!
//! SECURITY:
//! - Thin wrapper only
//! - No crypto logic
//! - Kill-aware
//! - Fail-closed
//!
//! ❄️ SUBJECT TO API FREEZE

#![deny(clippy::derive_debug)]

pub mod api;
pub mod error;
pub mod handle;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

#[cfg(target_os = "android")]
pub mod jni;

// ❄️ ONLY THESE ARE PUBLIC
pub use api::{Core, CoreError};
pub use error::BridgeError;
pub use handle::CoreHandle;pub mod jni;
