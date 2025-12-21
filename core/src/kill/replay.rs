//! Kill-message replay protection.
//!
//! Prevents reuse of old or duplicated kill commands.

use crate::device::fingerprint::device_id;
use std::sync::Mutex;

static LAST_KILL_TS: Mutex<u64> = Mutex::new(0);

pub fn check_and_update(ts: u64) -> bool {
    let mut last = LAST_KILL_TS.lock().unwrap();
    if ts <= *last {
        return false;
    }
    *last = ts;
    true
}
