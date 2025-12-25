//! Kill blob generator (ADMIN DEVICE ONLY).

#![cfg(feature = "kill-admin")]
#![deny(clippy::derive_debug)]

use crate::crypto::{
    aes_gcm,
    derive::{derive_key, Purpose},
};
use crate::device::registry::DeviceRegistry;
use crate::kill::build_kill_aad;
use crate::memory::{GuardedKey32, Secret};

use rand_core::{OsRng, RngCore};

/* ───────────── CONSTANTS ───────────── */

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const PLAINTEXT_LEN: usize = 1 + 32 + 8;

const KILL_VERSION_V1: u8 = 1;

/* ───────────── TYPES ───────────── */

pub struct KillRequest {
    pub target_device_id: [u8; 32],
    pub replay: u64,
}

/* ───────────── API ───────────── */

pub fn generate_kill_blob(
    root_key: &GuardedKey32,
    registry: &DeviceRegistry,
    req: KillRequest,
) -> Secret<Vec<u8>> {
    let mut kill_key = GuardedKey32::zeroed();

    derive_key(
        root_key,
        Purpose::Recovery,
        registry.device_fingerprint(),
        &mut kill_key,
    )
    .expect("kill key derivation must not fail");

    let plaintext = Secret::<Vec<u8>>::init_with(|buf| {
        *buf = vec![0u8; PLAINTEXT_LEN];
        buf[0] = KILL_VERSION_V1;
        buf[1..33].copy_from_slice(&req.target_device_id);
        buf[33..41].copy_from_slice(&req.replay.to_be_bytes());
    });

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let aad = build_kill_aad(registry);

    let mut out = vec![0u8; NONCE_LEN + PLAINTEXT_LEN + TAG_LEN];
    out[..NONCE_LEN].copy_from_slice(&nonce);

    aes_gcm::seal(
        &kill_key,
        &nonce,
        plaintext.borrow(),
        &aad,
        &mut out[NONCE_LEN..],
    )
    .expect("kill blob encryption must not fail");

    Secret::new(out)
}