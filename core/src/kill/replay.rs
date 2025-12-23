//! Kill replay protection.
//!
//! SECURITY:
//! - Persistent
//! - Monotonic
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
}

/// Check and record replay token.
///
/// Returns true if fresh.
pub fn check_and_commit(token: ReplayToken) -> bool {
    let mut log = match EncryptedLog::open_kill_log() {
        Ok(l) => l,
        Err(_) => return false,
    };

    let last = log.read_u64().unwrap_or(0);

    if token.0 <= last {
        return false;
    }

    log.write_u64(token.0).is_ok()
}
