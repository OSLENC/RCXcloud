
///! Argon2id KDF — direct write, no stack copies.

use crate::memory::{GuardedBox, GuardedKey32};
use argon2::{Argon2, Algorithm, Version, Params as AParams};

pub struct Params {
    pub mem_kib: u32,
    pub time: u32,
    pub lanes: u32,
}

impl Default for Params {
    fn default() -> Self {
        Self { mem_kib: 64 * 1024, time: 3, lanes: 1 }
    }
}

/// Derive a single purpose-bound key.
///
/// SECURITY:
/// - heap-only
/// - no stack secrets
/// - domain-separated
pub fn derive_single_key(
    input: &[u8],
    params: &Params,
    domain: &'static [u8],
    out: &mut GuardedKey32,
) -> Result<(), KdfError> {
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        AParams::new(params.mem_kib, params.time, params.lanes, Some(32))
            .map_err(|_| KdfError::Params)?,
    );

    argon.hash_password_into(input, domain, out.borrow_mut())
        .map_err(|_| KdfError::Derive)?;

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfError {
    Params,
    Derive,
}
