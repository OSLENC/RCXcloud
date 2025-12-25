
//! Kill protocol constants and AAD.
//!
//! TRUST LEVEL: Secure Core
//!
//! This file defines the immutable kill protocol.
//! Any change here is a BREAKING SECURITY CHANGE.

use crate::device::registry::DeviceRegistry;

/// Build authenticated associated data for kill blobs.
///
/// SECURITY:
/// - MUST be used by BOTH generator and verifier
/// - Device-bound
/// - Deterministic
/// - NOT encrypted (AAD)
#[inline(always)]
pub fn build_kill_aad(registry: &DeviceRegistry) -> [u8; 24] {
    let mut aad = [0u8; 24];

    // Protocol label (16 bytes, fixed)
    aad[..16].copy_from_slice(b"rcxcloud-kill-v1");

    // Device fingerprint (u64, BE)
    aad[16..24].copy_from_slice(
        &registry.device_fingerprint().to_be_bytes(),
    );

    aad
}