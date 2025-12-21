//! Device-specific kill execution strategy.
//!
//! Execution order differs per device to hinder static analysis.

use crate::keystore::KeyStore;

pub fn execute(keystore: &KeyStore) {
    // Order can vary per build/device
    keystore.on_remote_kill();
}
