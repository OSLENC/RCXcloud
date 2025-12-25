//! Kill verification strategy (STATELESS).
//!
//! TRUST LEVEL: Secure Core
//!
//! SECURITY GUARANTEES:
//! - No cached state
//! - Deterministic per-device polymorphism
//! - AEAD authenticated
//! - Fail-closed on all errors
//! - No stack-resident secrets
//! - Constant-time device binding

#![deny(clippy::derive_debug)]

use subtle::ConstantTimeEq;

use crate::crypto::{
    aes_gcm,
    derive::{derive_key, Purpose},
};
use crate::device::registry::DeviceRegistry;
use crate::kill::{build_kill_aad, replay::ReplayToken};
use crate::memory::{wipe_vec, GuardedKey32, Secret};

/* ───────────── CONSTANTS ───────────── */

/// AES-GCM nonce length (96-bit)
const NONCE_LEN: usize = 12;

/// AES-GCM authentication tag length
const TAG_LEN: usize = 16;

/// Kill protocol version
const KILL_VERSION_V1: u8 = 1;

/// Plaintext layout:
/// [ version (1) | device_id (32) | replay (8) ]
const PLAINTEXT_LEN: usize = 1 + 32 + 8;

/* ───────────── PUBLIC TYPES ───────────── */

/// Authenticated kill decision (NON-SECRET).
pub struct KillDecision {
    pub replay: ReplayToken,
}

/* ───────────── ENTRY POINT ───────────── */

/// Verify and authenticate a kill blob.
///
/// Returns `Some(KillDecision)` iff:
/// - AEAD authentication succeeds
/// - Protocol version matches
/// - Device binding matches (constant-time)
/// - Replay token parses correctly
///
/// FAIL-CLOSED on all errors.
pub fn verify_kill_blob(
    registry: &DeviceRegistry,
    root_key: &GuardedKey32,
    blob: &[u8],
) -> Option<KillDecision> {
    /* ───── Derive per-device kill key ───── */

    let mut kill_key = GuardedKey32::zeroed();

    derive_key(
        root_key,
        Purpose::Recovery,
        registry.device_fingerprint(),
        &mut kill_key,
    )
    .ok()?;

    /* ───── Build authenticated associated data ───── */

    let aad = build_kill_aad(registry);

    /* ───── Decrypt + authenticate blob ───── */

    let plaintext = decrypt_blob(&kill_key, blob, &aad)?;

    /* ───── Parse payload ───── */

    let parsed = parse_payload(plaintext.borrow())?;

    /* ───── Constant-time device binding ───── */

    if parsed
        .device_id
        .ct_eq(&registry.device_id())
        .into()
        == false
    {
        return None;
    }

    Some(KillDecision {
        replay: parsed.replay,
    })
}

/* ───────────── INTERNAL TYPES ───────────── */

struct ParsedKill {
    device_id: [u8; 32],
    replay: ReplayToken,
}

/* ───────────── INTERNAL HELPERS ───────────── */

/// Decrypt and authenticate kill blob.
///
/// Expected format:
/// [ nonce (12) | ciphertext | tag (16) ]
fn decrypt_blob(
    key: &GuardedKey32,
    blob: &[u8],
    aad: &[u8],
) -> Option<Secret<Vec<u8>>> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return None;
    }

    let nonce: &[u8; NONCE_LEN] = blob[..NONCE_LEN].try_into().ok()?;
    let ciphertext = &blob[NONCE_LEN..];

    let mut plaintext = vec![0u8; ciphertext.len() - TAG_LEN];

    let ok = aes_gcm::open(
        key,
        nonce,
        ciphertext,
        aad,
        &mut plaintext,
    );

    if !ok {
        wipe_vec(&mut plaintext);
        return None;
    }

    if plaintext.len() != PLAINTEXT_LEN {
        wipe_vec(&mut plaintext);
        return None;
    }

    if plaintext[0] != KILL_VERSION_V1 {
        wipe_vec(&mut plaintext);
        return None;
    }

    Some(Secret::new(plaintext))
}

/// Parse authenticated kill payload.
///
/// ASSUMES:
/// - AEAD authentication already succeeded
/// - Length already verified
fn parse_payload(buf: &[u8]) -> Option<ParsedKill> {
    let mut device_id = [0u8; 32];
    device_id.copy_from_slice(&buf[1..33]);

    let replay = ReplayToken::from_bytes(&buf[33..41])?;

    Some(ParsedKill {
        device_id,
        replay,
    })
}