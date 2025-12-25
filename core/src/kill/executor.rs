//! Terminal kill executor (Secure Core).

use core::sync::atomic::Ordering;

use crate::keystore::master::GLOBAL_KILLED;
use crate::keystore::KeyStore;
use crate::device::registry::DeviceRegistry;
use crate::kill::replay::{ReplayToken, check_and_commit};

#[derive(Debug)]
pub enum KillError {
    ReplayDetected,
}

/// Execute irreversible device kill.
///
/// Returns Err if rejected (replay).
/// Never returns on success.
pub fn execute_kill(
    keystore: &KeyStore,
    registry: &DeviceRegistry,
    replay: ReplayToken,
) -> ! {
    // 1️⃣ Replay protection (FAIL CLOSED)
    if !check_and_commit(replay) {
        return Err(KillError::ReplayDetected);
    }

    // 2️⃣ GLOBAL KILL FUSE — FIRST (memory barrier)
    GLOBAL_KILLED.store(true, Ordering::SeqCst);

    // 3️⃣ Disable all plugins immediately
    plugins::disable_all();

    // 4️⃣ WIPE keystore (IRREVERSIBLE)
    // This permanently transitions keystore into KILLED state.
    keystore.wipe();

    // 5️⃣ Persist device kill marker (best effort)
    let _ = registry.mark_this_device_killed();

    // 6️⃣ Terminal halt (no return)
    loop {
        core::hint::spin_loop();
    }
}