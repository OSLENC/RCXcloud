
//! Argon2id KDF — heap-only, misuse-resistant.
//!
//! TRUST LEVEL: Secure Core
//!
//! FORMAL INVARIANTS (ENFORCED):
//! - Inputs MUST be heap-backed
//! - No stack-resident secret outputs
//! - All outputs written into GuardedKey32
//! - Deterministic zeroization on drop
//! - Bounded resource usage
//! - Fail-closed

use crate::memory::GuardedKey32;
use argon2::{Argon2, Algorithm, Version, Params as AParams};
use zeroize::Zeroizing;

/* ───────────── PARAMETERS ───────────── */

/// Argon2 parameters (non-secret).
///
/// SECURITY:
/// - Bounds enforced internally
/// - Caller cannot cause OOM or DoS
#[derive(Clone, Copy)]
pub struct Params {
    pub mem_kib: u32,
    pub time: u32,
    pub lanes: u32,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            mem_kib: 64 * 1024, // 64 MiB
            time: 3,
            lanes: 1,
        }
    }
}

/* ───────────── LIMITS ───────────── */

const MIN_MEM_KIB: u32 = 8 * 1024;      // 8 MiB
const MAX_MEM_KIB: u32 = 512 * 1024;    // 512 MiB
const MIN_LANES: u32 = 1;
const MAX_LANES: u32 = 4;
const MIN_TIME: u32 = 1;
const MAX_TIME: u32 = 10;

/* ───────────── PUBLIC API ───────────── */

/// Derive a single 256-bit key using Argon2id.
///
/// SECURITY:
/// - Input MUST be heap-backed (`Zeroizing<Vec<u8>>`)
/// - Salt MUST be explicit and non-empty
/// - Output written directly into GuardedKey32
/// - No stack secrets
pub fn derive_single_key(
    input: &Zeroizing<Vec<u8>>,
    salt: &[u8],
    params: &Params,
    out: &mut GuardedKey32,
) -> Result<(), KdfError> {
    validate_inputs(input, salt)?;
    validate_params(params)?;

    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        AParams::new(
            params.mem_kib,
            params.time,
            params.lanes,
            Some(32),
        )
        .map_err(|_| KdfError::Params)?,
    );

    argon
        .hash_password_into(input, salt, out.borrow_mut())
        .map_err(|_| KdfError::Derive)?;

    Ok(())
}

/// Derive **two independent 256-bit keys** (e.g. recovery root + session).
///
/// OUTPUTS:
/// - `out_root`    → GuardedKey32
/// - `out_session` → GuardedKey32
///
/// SECURITY:
/// - Replaces forbidden `[u8; 64]` stack output
/// - Each key is independently guarded and zeroized
pub fn derive_two_keys(
    input: &Zeroizing<Vec<u8>>,
    salt: &[u8],
    params: &Params,
    out_root: &mut GuardedKey32,
    out_session: &mut GuardedKey32,
) -> Result<(), KdfError> {
    validate_inputs(input, salt)?;
    validate_params(params)?;

    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        AParams::new(
            params.mem_kib,
            params.time,
            params.lanes,
            Some(64),
        )
        .map_err(|_| KdfError::Params)?,
    );

    // Temporary heap buffer (NOT stack)
    let mut tmp = Zeroizing::new(vec![0u8; 64]);

    argon
        .hash_password_into(input, salt, &mut tmp)
        .map_err(|_| KdfError::Derive)?;

    out_root
        .borrow_mut()
        .copy_from_slice(&tmp[..32]);

    out_session
        .borrow_mut()
        .copy_from_slice(&tmp[32..64]);

    Ok(())
}

/* ───────────── VALIDATION ───────────── */

#[inline(always)]
fn validate_inputs(
    input: &Zeroizing<Vec<u8>>,
    salt: &[u8],
) -> Result<(), KdfError> {
    if input.is_empty() || salt.is_empty() {
        return Err(KdfError::InvalidInput);
    }
    Ok(())
}

#[inline(always)]
fn validate_params(params: &Params) -> Result<(), KdfError> {
    if !(MIN_MEM_KIB..=MAX_MEM_KIB).contains(&params.mem_kib) {
        return Err(KdfError::Params);
    }
    if !(MIN_TIME..=MAX_TIME).contains(&params.time) {
        return Err(KdfError::Params);
    }
    if !(MIN_LANES..=MAX_LANES).contains(&params.lanes) {
        return Err(KdfError::Params);
    }
    Ok(())
}

/* ───────────── ERRORS ───────────── */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfError {
    InvalidInput,
    Params,
    Derive,
}
