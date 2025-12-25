//! Terminal kill executor (Secure Core).

use core::sync::atomic::Ordering;
use std::process;

use crate::keystore::master::GLOBAL_KILLED;
use crate::keystore::KeyStore;
use crate::device::registry::DeviceRegistry;
use crate::kill::replay::{ReplayToken, check_and_commit};

#[derive(Debug)]
pub enum KillError {
    ReplayDetected,
    IoFailure,
}

/// Execute irreversible device kill.
///
/// Returns Err if rejected (replay).
/// If successful, this function NEVER returns (process abort).
pub fn execute_kill(
    keystore: &KeyStore,
    registry: &DeviceRegistry,
    replay: ReplayToken,
) -> Result<(), KillError> {
    // 1️⃣ Replay protection (FAIL CLOSED)
    if !check_and_commit(replay) {
        return Err(KillError::ReplayDetected);
    }

    // 2️⃣ GLOBAL KILL FUSE — FIRST (memory barrier)
    GLOBAL_KILLED.store(true, Ordering::SeqCst);

    // 3️⃣ WIPE keystore (IRREVERSIBLE)
    // Locking forces a memory wipe of the active keys
    keystore.lock();

    // 4️⃣ Persist device kill marker (best effort)
    let _ = registry.mark_this_device_killed();

    // 5️⃣ Terminal halt (no return)
    // We intentionally crash the process to ensure no secret material remains in RAM.
    loop {
        process::abort();
    }
}
