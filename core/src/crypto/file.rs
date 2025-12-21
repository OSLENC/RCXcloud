//! File chunk encryption pipeline (Secure Core).
//!
//! TRUST LEVEL: Secure Core
//!
//! FORMAL INVARIANTS:
//! - No raw crypto primitives exposed
//! - All encryption goes through Session
//! - Deterministic nonce + typed AAD only
//! - Chunk boundaries are explicit
//! - No plaintext persistence
//! - Fail-closed on any error

#![deny(clippy::derive_debug)]

use crate::crypto::aad::Aad;
use crate::keystore::session::{Session, SessionError};
use crate::keystore::session::{EncryptResult, VerifyResult};

/// File identifier (stable, non-secret).
pub type FileId = u64;

/// Cloud identifier (stable, non-secret).
pub type CloudId = u16;

/// Versioned encryption format.
pub const FILE_CRYPTO_VERSION: u8 = 1;

/// Encrypt a single file chunk.
///
/// INPUT:
/// - plaintext chunk
/// - chunk index
///
/// OUTPUT:
/// - ciphertext `[ciphertext | tag]`
///
/// SECURITY:
/// - Nonce is derived internally
/// - AAD is typed and versioned
pub fn encrypt_chunk(
    session: &mut Session,
    file_id: FileId,
    cloud_id: CloudId,
    chunk_index: u32,
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<EncryptResult, SessionError> {
    let aad = Aad {
        file_id,
        chunk: chunk_index,
        cloud_id,
        version: FILE_CRYPTO_VERSION,
    };

    session.encrypt(plaintext, aad, out)
}

/// Decrypt + verify a single file chunk.
///
/// SECURITY:
/// - Authentication happens BEFORE plaintext exposure
/// - Output buffer is zeroed on failure (inside crypto)
pub fn decrypt_chunk(
    session: &mut Session,
    file_id: FileId,
    cloud_id: CloudId,
    chunk_index: u32,
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<VerifyResult, SessionError> {
    let aad = Aad {
        file_id,
        chunk: chunk_index,
        cloud_id,
        version: FILE_CRYPTO_VERSION,
    };

    session.decrypt_verify(ciphertext, aad, out)
}