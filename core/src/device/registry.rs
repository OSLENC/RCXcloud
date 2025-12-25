//! Device registry (Secure Core).
//!
//! TRUST LEVEL: Secure Core
//!
//! PURPOSE:
//! - Persist stable device identity
//! - Persist irreversible kill state
//! - Provide deterministic device identifiers
//!
//! AUTHORITATIVE KILL SEMANTICS:
//! - Device is killed IFF a kill record EXISTS
//! - Kill state is append-only and irreversible
//! - Any storage error => FAIL CLOSED (killed)
//!
//! SECURITY INVARIANTS:
//! - No secrets stored
//! - Identity is fixed-size and overwrite-only
//! - Kill state is append-only and monotonic
//! - No panics
//! - Deterministic decoding

#![deny(clippy::derive_debug)]

use crate::device::fingerprint::DeviceFingerprint;
use crate::integrity::hash::hash_sha256;
use crate::logging::encrypted::EncryptedLog;

/* ───────────── TYPES ───────────── */

/// Persistent device registry (identity + kill marker).
pub struct DeviceRegistry {
    device_id: [u8; 32],
    fingerprint: DeviceFingerprint,
}

/* ───────────── ERRORS ───────────── */

#[derive(Debug)]
pub enum RegistryError {
    Storage,
    Corrupt,
}

/* ───────────── IMPLEMENTATION ───────────── */

impl DeviceRegistry {
    /* ───────────── INITIALIZATION ───────────── */

    /// Load or initialize device registry.
    ///
    /// SECURITY:
    /// - Must be called exactly once at startup
    /// - Fixed-size identity (40 bytes)
    /// - Fails closed on corruption or IO error
    pub fn load_or_init(
        device_material: &[u8],
    ) -> Result<Self, RegistryError> {
        let mut id_log =
            EncryptedLog::open_device_identity()
                .map_err(|_| RegistryError::Storage)?;

        // ───── Try load existing identity ─────
        if let Some(buf) =
            id_log.read_fixed().map_err(|_| RegistryError::Storage)?
        {
            return Self::decode_identity(&buf);
        }

        // ───── First-time initialization ─────
        let hash = hash_sha256(device_material);
        let fingerprint = DeviceFingerprint::from_material(device_material);

        let mut buf = Vec::with_capacity(40);
        buf.extend_from_slice(hash.as_ref());
        buf.extend_from_slice(&fingerprint.as_u64().to_be_bytes());

        id_log
            .write_fixed(&buf)
            .map_err(|_| RegistryError::Storage)?;

        Ok(Self {
            device_id: *hash.as_ref(),
            fingerprint,
        })
    }

    /* ───────────── ACCESSORS ───────────── */

    /// Stable logical device ID (non-secret).
    #[inline(always)]
    pub fn device_id(&self) -> [u8; 32] {
        self.device_id
    }

    /// Stable device fingerprint (non-secret).
    #[inline(always)]
    pub fn device_fingerprint(&self) -> u64 {
        self.fingerprint.as_u64()
    }

    /* ───────────── KILL STATE ───────────── */

    /// Check if device is permanently killed.
    ///
    /// SEMANTICS:
    /// - Killed iff ANY kill record exists
    /// - Fail-closed on any error
    pub fn is_killed(&self) -> bool {
        let mut log = match EncryptedLog::open_device_kill_log() {
            Ok(l) => l,
            Err(_) => return true, // FAIL CLOSED
        };

        match log.has_any_content() {
            Ok(records) => !records.is_empty(),
            Err(_) => true, // FAIL CLOSED
        }
    }

    /// Permanently mark this device as killed.
    ///
    /// SECURITY:
    /// - Append-only
    /// - Irreversible
    /// - Crash-safe
    pub fn mark_this_device_killed(
        &self,
    ) -> Result<(), RegistryError> {
        let mut log =
            EncryptedLog::open_device_kill_log()
                .map_err(|_| RegistryError::Storage)?;

        log.append_record(b"KILLED")
            .map_err(|_| RegistryError::Storage)
    }

    /* ───────────── INTERNAL ───────────── */

    fn decode_identity(buf: &[u8]) -> Result<Self, RegistryError> {
        if buf.len() != 40 {
            return Err(RegistryError::Corrupt);
        }

        let mut id = [0u8; 32];
        id.copy_from_slice(&buf[..32]);

        let mut fp = [0u8; 8];
        fp.copy_from_slice(&buf[32..40]);

        let fingerprint =
            DeviceFingerprint::from_u64(u64::from_be_bytes(fp));

        Ok(Self {
            device_id: id,
            fingerprint,
        })
    }
}
