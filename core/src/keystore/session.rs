//! Active cryptographic session (OPERATION-BASED).
//!
//! TRUST LEVEL: Secure Core

#![deny(clippy::derive_debug)]

use crate::crypto::{
    aes_gcm,
    derive::{derive_key, Purpose},
    nonce::derive_nonce,
};
use crate::keystore::master::GLOBAL_KILLED;
use crate::memory::GuardedKey32;

use core::marker::PhantomData;
use core::sync::atomic::Ordering;

/* ───────────── OUTPUT TYPES ───────────── */

#[derive(Clone, Copy)]
pub struct EncryptResult {
    pub total_len: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyResult(pub bool, pub usize);

/* ───────────── ERRORS ───────────── */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    Killed,
    Locked,
    InvalidInput,
    OutputTooSmall,
    CryptoFailure,
}

/* ───────────── SESSION TYPE ───────────── */

pub struct Session {
    session_key: Option<GuardedKey32>,
    _no_send_sync: PhantomData<*const ()>,
}

impl Session {
    pub(crate) fn new(session_key: GuardedKey32) -> Self {
        Self {
            session_key: Some(session_key),
            _no_send_sync: PhantomData,
        }
    }

    #[inline(always)]
    fn require_alive(&self) -> Result<&GuardedKey32, SessionError> {
        if GLOBAL_KILLED.load(Ordering::SeqCst) {
            return Err(SessionError::Killed);
        }
        self.session_key.as_ref().ok_or(SessionError::Locked)
    }

    /* ───────────── ENCRYPT ───────────── */

    pub fn encrypt_chunk(
        &self,
        file_id: u64,
        _cloud_id: u16, // Ignored by current nonce spec
        chunk: u32,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<EncryptResult, SessionError> {
        let session_key = self.require_alive()?;

        let required = plaintext.len() + aes_gcm::TAG_LEN;
        if out.len() < required {
            return Err(SessionError::OutputTooSmall);
        }

        let mut enc_key = GuardedKey32::zeroed();

        // ✅ FIX: Use Purpose::FileEncryption and u64 context
        derive_key(
            session_key,
            Purpose::FileEncryption,
            file_id,
            &mut enc_key,
        )
        .map_err(|_| SessionError::CryptoFailure)?;

        // ✅ FIX: Pass the key to derive_nonce
        let nonce = derive_nonce(&enc_key, file_id, chunk);

        let ct_len = aes_gcm::encrypt(
            &enc_key,
            &nonce,
            plaintext,
            &[], // No AAD for chunks
            out,
        )
        .map_err(|_| SessionError::CryptoFailure)?;

        Ok(EncryptResult {
            total_len: ct_len,
        })
    }

    /* ───────────── DECRYPT ───────────── */

    pub fn decrypt_chunk(
        &self,
        file_id: u64,
        _cloud_id: u16,
        chunk: u32,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<VerifyResult, SessionError> {
        let session_key = self.require_alive()?;

        if ciphertext.len() < aes_gcm::TAG_LEN {
            return Err(SessionError::InvalidInput);
        }

        let mut enc_key = GuardedKey32::zeroed();

        derive_key(
            session_key,
            Purpose::FileEncryption,
            file_id,
            &mut enc_key,
        )
        .map_err(|_| SessionError::CryptoFailure)?;

        let nonce = derive_nonce(&enc_key, file_id, chunk);

        let pt_len = aes_gcm::decrypt(
            &enc_key,
            &nonce,
            ciphertext,
            &[],
            out,
        )
        .map_err(|_| SessionError::CryptoFailure)?;

        Ok(VerifyResult(true, pt_len))
    }
}
