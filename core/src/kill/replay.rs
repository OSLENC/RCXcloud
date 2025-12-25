//! Kill replay protection.
//!
//! SECURITY:
//! - Persistent
//! - Monotonic
//! - Append-only
//! - Fail-closed

use crate::logging::encrypted::EncryptedLog;

#[derive(Clone, Copy)]
pub struct ReplayToken(u64);

impl ReplayToken {
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != 8 {
            return None;
        }
        Some(Self(u64::from_be_bytes(b.try_into().ok()?)))
    }

    #[inline(always)]
    pub fn value(self) -> u64 {
        self.0
    }
}

/// Check and persist replay token.
///
/// Semantics:
/// - Reads last committed token (if any)
/// - Rejects non-increasing values
/// - Appends new token (never overwrites)
///
/// FAIL-CLOSED on any error.
pub fn check_and_commit(token: ReplayToken) -> bool {
    let mut log = match EncryptedLog::open_device_kill_log() {
        Ok(l) => l,
        Err(_) => return false,
    };

    let last = match log.read_last_u64() {
        Ok(Some(v)) => v,
        Ok(None) => 0,
        Err(_) => return false,
    };

    if token.value() <= last {
        return false;
    }

    log.append_u64(token.value()).is_ok()
}