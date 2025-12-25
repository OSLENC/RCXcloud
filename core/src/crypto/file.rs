

//! File chunk encryption pipeline (Secure Core).
//!
//! TRUST LEVEL: Secure Core
//!
//! SECURITY INVARIANTS:
//! - Explicit chunk boundaries
//! - AEAD format enforced
//! - Fail-closed on all errors
//! - Output buffers wiped on failure
//! - No plaintext persistence

#![deny(clippy::derive_debug)]

use crate::crypto::aad::{Aad, AAD_VERSION_V1};
use crate::crypto::aes_gcm::TAG_LEN;
use crate::keystore::session::{EncryptResult, Session, SessionError, VerifyResult};

pub type FileId = u64;
pub type CloudId = u16;

/// Maximum allowed plaintext chunk size (DoS-safe).
pub const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/* ───────────── ENCRYPT ───────────── */

/// Encrypt a single file chunk.
///
/// Output format:
/// `[ ciphertext | tag ]`
pub fn encrypt_chunk(
    session: &mut Session,
    file_id: FileId,
    cloud_id: CloudId,
    chunk_index: u32,
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<EncryptResult, SessionError> {
    // ───── Input validation ─────

    if plaintext.len() > MAX_CHUNK_SIZE {
        out.fill(0);
        return Err(SessionError::InvalidInput);
    }

    let required_len = plaintext.len() + TAG_LEN;
    if out.len() != required_len {
        out.fill(0);
        return Err(SessionError::OutputTooSmall);
    }

    let aad = Aad::new(
        file_id,
        chunk_index,
        cloud_id,
        AAD_VERSION_V1,
    )
    .ok_or_else(|| {
        out.fill(0);
        SessionError::InvalidInput
    })?;

    // ───── Encrypt via session ─────

    match session.encrypt(plaintext, aad, out) {
        Ok(r) => Ok(r),
        Err(e) => {
            out.fill(0);
            Err(e)
        }
    }
}

/* ───────────── DECRYPT ───────────── */

/// Decrypt + verify a single file chunk.
///
/// Returns VerifyResult(false) on auth failure.
pub fn decrypt_chunk(
    session: &mut Session,
    file_id: FileId,
    cloud_id: CloudId,
    chunk_index: u32,
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<VerifyResult, SessionError> {
    // ───── Input validation ─────

    if ciphertext.len() < TAG_LEN {
        out.fill(0);
        return Err(SessionError::InvalidInput);
    }

    let ct_len = ciphertext.len() - TAG_LEN;

    if ct_len > MAX_CHUNK_SIZE {
        out.fill(0);
        return Err(SessionError::InvalidInput);
    }

    if out.len() != ct_len {
        out.fill(0);
        return Err(SessionError::OutputTooSmall);
    }

    let aad = Aad::new(
        file_id,
        chunk_index,
        cloud_id,
        AAD_VERSION_V1,
    )
    .ok_or_else(|| {
        out.fill(0);
        SessionError::InvalidInput
    })?;

    // ───── Decrypt via session ─────

    match session.decrypt_verify(ciphertext, aad, out) {
        Ok(v) => Ok(v),
        Err(e) => {
            out.fill(0);
            Err(e)
        }
    }
}

