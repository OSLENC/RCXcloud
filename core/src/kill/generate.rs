//! Kill blob generator (ADMIN DEVICE ONLY).
//!
//! ⚠️ MUST NEVER be compiled into target devices.
//!
//! Kill Blob Format (v1):
//! [ NONCE | CIPHERTEXT | TAG ]
//!
//! Plaintext:
//! [0..32]  Device ID
//! [32..40] Replay Token (u64 BE)

#![cfg(feature = "kill-admin")]
#![deny(clippy::derive_debug)]

use crate::crypto::{
    aes_gcm,
    derive::{derive_key, Purpose},
};
use crate::device::registry::DeviceRegistry;
use crate::memory::{GuardedKey32, Secret};

use rand_core::{OsRng, RngCore};

/* ───────────── CONSTANTS ───────────── */

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const PLAINTEXT_LEN: usize = 32 + 8;

/* ───────────── TYPES ───────────── */

pub struct KillRequest {
    pub target_device_id: [u8; 32],
    pub replay: u64,
}

/* ───────────── PUBLIC API ───────────── */

pub fn generate_kill_blob(
    root_key: &GuardedKey32,
    registry: &DeviceRegistry,
    req: KillRequest,
) -> Secret<Vec<u8>> {
    /* ───── Derive per-device kill key ───── */

    let kill_key = derive_key(
        root_key,
        Purpose::Recovery,
        registry.device_fingerprint(),
    )
    .expect("kill key derivation must not fail");

    /* ───── Build plaintext (heap-only) ───── */

    let plaintext = Secret::<Vec<u8>>::init_with(|buf| {
        *buf = vec![0u8; PLAINTEXT_LEN];
        buf[0..32].copy_from_slice(&req.target_device_id);
        buf[32..40].copy_from_slice(&req.replay.to_be_bytes());
    });

    /* ───── Nonce ───── */

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    /* ───── Encrypt (AEAD, empty AAD v1) ───── */

    let mut out = vec![0u8; NONCE_LEN + PLAINTEXT_LEN + TAG_LEN];
    out[..NONCE_LEN].copy_from_slice(&nonce);

    aes_gcm::seal(
        &kill_key,
        &nonce,
        plaintext.borrow(),
        &[], // AAD = empty (v1)
        &mut out[NONCE_LEN..],
    )
    .expect("kill blob encryption must not fail");

    Secret::new(out)
}
