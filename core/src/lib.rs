//! RCXCloud Secure Core
//!
//! TRUST LEVEL: Secure Core (Trust Anchor)
//!
//! SECURITY MODEL (AUTHORITATIVE):
//! - Zero-trust
//! - Fail-closed
//! - Deterministic by default
//! - Irreversible kill semantics
//! - No network, no cloud, no async
//!
//! PUBLIC SURFACE RULE:
//! - ONLY `bridge::*` is public to the outside world
//! - All other modules are INTERNAL and MUST NOT be re-exported
//!
//! ❄️ SUBJECT TO SECURE CORE API FREEZE ❄️

// ─────────────────────────────────────────────
// SECURITY & SAFETY LINTS (GLOBAL)
// ─────────────────────────────────────────────

// Unsafe code is forbidden by default.
// Modules that REQUIRE unsafe (FFI / memory locking)
// MUST explicitly opt-in with `#![allow(unsafe_code)]`.
#![deny(unsafe_code)]

// No hidden control-flow escapes.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![forbid(clippy::panic)]

// ─────────────────────────────────────────────
// INTERNAL MODULES (STRICTLY PRIVATE)
// ─────────────────────────────────────────────
//
// These modules form the Secure Core trust anchor.
// They MUST NOT be publicly re-exported.

mod crypto;
mod device;
mod integrity;
mod keystore;
mod kill;
mod logging;
mod memory;
mod policy;

// ─────────────────────────────────────────────
// MEDIA PIPELINE (DESKTOP ONLY)
// ─────────────────────────────────────────────
//
// Media parsing is hostile-input handling.
// It belongs in Secure Core, BUT MUST NEVER exist on Android.
//
// Rule:
// - Media compiles ONLY when:
//   - NOT Android
//   - feature "desktop-media" is enabled

#[cfg(all(not(target_os = "android"), feature = "desktop-media"))]
mod media;

// ─────────────────────────────────────────────
// BRIDGE (ONLY PUBLIC ENTRY POINT)
// ─────────────────────────────────────────────
//
// The bridge module defines the ONLY stable integration surface
// for JNI / C / WASM / Plugins.

pub mod bridge;

// ─────────────────────────────────────────────
// COMPILATION SAFETY CHECKS
// ─────────────────────────────────────────────

// Android builds MUST explicitly enable the `android` feature.
// Prevents accidental JNI linkage or misconfigured builds.
#[cfg(all(target_os = "android", not(feature = "android")))]
compile_error!(
    "Android builds MUST enable the `android` feature in Cargo.toml"
);

// Media MUST NEVER be built on Android — even accidentally.
#[cfg(all(target_os = "android", feature = "desktop-media"))]
compile_error!(
    "desktop-media feature is FORBIDDEN on Android targets"
);

// Load JNI bindings ONLY when explicitly requested.
#[cfg(feature = "android")]
use bridge::jni;

// Load WASM bindings ONLY for wasm32 targets.
#[cfg(target_arch = "wasm32")]
use bridge::wasm;