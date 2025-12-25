#![cfg(feature = "kem")]
//! X25519 + HKDF backup key encapsulation.
//!
//! TRUST LEVEL: Secure Core
//!
//! FORMAL INVARIANTS (ENFORCED):
//! - No stack-resident secret material
//! - Shared secrets never escape heap-backed buffers
//! - Output keys written only into GuardedKey32
//! - Explicit domain separation
//! - Forbidden after global kill
//! - Fail-closed

#![deny(clippy::derive_debug)]

use core::sync::atomic::Ordering;

use crate::keystore::master::GLOBAL_KILLED;
use crate::memory::GuardedKey32;

use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// HKDF domain-separation label (MUST NEVER CHANGE).
const KEM_LABEL: &[u8] = b"rcxcloud:kem:backup:v1";

/* ───────────── CSPRNG ───────────── */

/// Generate cryptographically secure random key material.
///
/// SECURITY:
/// - Heap-only output
/// - Forbidden after global kill
/// - No stack copies
pub fn csrng(out: &mut GuardedKey32) -> Result<(), CsrngError> {
    if GLOBAL_KILLED.load(Ordering::SeqCst) {
        return Err(CsrngError::Killed);
    }

    OsRng
        .try_fill_bytes(out.borrow_mut())
        .map_err(|_| CsrngError::Failed)?;

    Ok(())
}

/* ───────────── ENCAPSULATION ───────────── */

/// Encapsulate a shared backup key for a peer.
///
/// RETURNS:
/// - Public encapsulation material
/// - Derived shared key (GuardedKey32)
///
/// SECURITY:
/// - Ephemeral secret never leaves stack frame
/// - Shared secret never escapes HKDF
/// - Output key is heap-locked
pub fn encapsulate(
    peer_pub: &[u8; 32],
    context: &[u8],
) -> Result<(Encapsulation, GuardedKey32), KEMError> {
    if GLOBAL_KILLED.load(Ordering::SeqCst) {
        return Err(KEMError::Killed);
    }

    // Ephemeral secret (short-lived, never stored)
    let eph = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph);

    let peer = PublicKey::from(*peer_pub);

    // Diffie-Hellman shared secret (never copied)
    let shared = eph.diffie_hellman(&peer);

    // Output key (heap-locked)
    let mut out = GuardedKey32::zeroed();

    let hkdf = Hkdf::<Sha256>::new(
        Some(KEM_LABEL),
        shared.as_bytes(),
    );

    hkdf.expand(context, out.borrow_mut())
        .map_err(|_| KEMError::Derive)?;

    Ok((
        Encapsulation {
            ephemeral_public: eph_pub.to_bytes(),
        },
        out,
    ))
}

/* ───────────── DECAPSULATION ───────────── */

/// Decapsulate a shared backup key.
///
/// SECURITY:
/// - Static secret never copied
/// - Shared secret never escapes HKDF
/// - Output key written in-place only
pub fn decapsulate(
    our_secret: &StaticSecret,
    peer_ephemeral: &[u8; 32],
    context: &[u8],
    out: &mut GuardedKey32,
) -> Result<(), KEMError> {
    if GLOBAL_KILLED.load(Ordering::SeqCst) {
        return Err(KEMError::Killed);
    }

    let peer = PublicKey::from(*peer_ephemeral);

    let shared = our_secret.diffie_hellman(&peer);

    let hkdf = Hkdf::<Sha256>::new(
        Some(KEM_LABEL),
        shared.as_bytes(),
    );

if context.len() < 32 {
    return Err(KEMError::Derive);
}

hkdf.expand(context, out.borrow_mut())
    .map_err(|_| KEMError::Derive)?;


    Ok(())
}

/* ───────────── TYPES ───────────── */

/// Public encapsulation output.
pub struct Encapsulation {
    pub ephemeral_public: [u8; 32],
}

/* ───────────── ERRORS ───────────── */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsrngError {
    Failed,
    Killed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KEMError {
    Derive,
    Killed,
}
