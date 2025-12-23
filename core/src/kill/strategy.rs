//! Kill verification strategy (STATELESS).
//!
//! TRUST LEVEL: Secure Core
//!
//! SECURITY:
//! - No cached state
//! - Deterministic per-device polymorphism
//! - AEAD authenticated
//! - Fail-closed
//! - No stack-resident secrets

use crate::crypto::{
    derive::{derive_key, Purpose},
    aes_gcm,
};
use crate::memory::{GuardedKey32, Secret, wipe_vec};
use crate::device::registry::DeviceRegistry;
use crate::kill::replay::ReplayToken;
use subtle::ConstantTimeEq;

/* ───────────── CONSTANTS ───────────── */

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KILL_VERSION_V1: u8 = 1;
const PLAINTEXT_LEN: usize = 49;

/* ───────────── PUBLIC TYPES ───────────── */

/// Parsed kill decision (NON-SECRET).
pub struct KillDecision {
    pub replay: ReplayToken,
}

/* ───────────── ENTRY POINT ───────────── */

/// Verify and authenticate a kill blob.
///
/// Returns `Some(KillDecision)` if valid.
pub fn verify_kill_blob(
    registry: &DeviceRegistry,
    root_key: &GuardedKey32,
    blob: &[u8],
) -> Option<KillDecision> {
    // 1️⃣ Derive per-device polymorphic kill key
    let kill_key = derive_key(
        root_key,
        Purpose::Recovery,
        registry.device_fingerprint(),
    ).ok()?;

    // 2️⃣ Build kill AAD
    let aad = build_kill_aad(registry);

    // 3️⃣ Decrypt + authenticate blob (AEAD)
    let plaintext = decrypt_blob(&kill_key, blob, &aad)?;

    // 4️⃣ Parse payload
    let parsed = parse_payload(plaintext.borrow())?;

    // 5️⃣ Verify target device binding (constant-time)
    if parsed.device_id.ct_eq(&registry.device_id()).into() == false {
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

/// Build authenticated associated data for kill blob.
///
/// AAD is NOT encrypted but MUST match exactly.
fn build_kill_aad(registry: &DeviceRegistry) -> [u8; 24] {
    let mut aad = [0u8; 24];

    // "rcxcloud-kill-v1"
    aad[..16].copy_from_slice(b"rcxcloud-kill-v1");

    // fingerprint (u64 BE)
    aad[16..24].copy_from_slice(
        &registry.device_fingerprint().to_be_bytes()
    );

    aad
}

/// AES-GCM decrypt + authenticate kill blob.
///
/// Format:
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
fn parse_payload(buf: &[u8]) -> Option<ParsedKill> {
    if buf.len() != PLAINTEXT_LEN {
        return None;
    }

    let mut device_id = [0u8; 32];
    device_id.copy_from_slice(&buf[1..33]);

    let replay = ReplayToken::from_bytes(&buf[33..41])?;

    Some(ParsedKill {
        device_id,
        replay,
    })
}
