//! WASM / C ABI bridge for Secure Core.
//!
//! SECURITY:
//! - Panic-safe
//! - Kill-aware
//! - Random Handle Generation
//! - Fail-closed

use crate::bridge::api::Core;
use crate::bridge::error::BridgeError;
use crate::bridge::handle::CoreHandle;
use crate::keystore::master::GLOBAL_KILLED;

use core::num::NonZeroU64;
use core::sync::atomic::Ordering;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::OnceLock;
use rand_core::{OsRng, RngCore};

/* ───────────── GLOBAL CORE REGISTRY ───────────── */

static CORE: OnceLock<Core> = OnceLock::new();
static CORE_ID: OnceLock<NonZeroU64> = OnceLock::new();

/* ───────────── HELPERS ───────────── */

#[inline(always)]
fn killed() -> bool {
    GLOBAL_KILLED.load(Ordering::SeqCst)
}

/* ───────────── ABI ───────────── */

#[no_mangle]
pub extern "C" fn rcx_init(out_handle: *mut u64) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_handle.is_null() || killed() {
            return Err(BridgeError::Killed);
        }

        CORE.get_or_init(Core::new);

        // ✅ FIX: Generate random handle, do not use hardcoded '1'
        let mut bytes = [0u8; 8];
        OsRng.fill_bytes(&mut bytes);
        let val = u64::from_ne_bytes(bytes);
        // Ensure non-zero (fallback to 1 if RNG yields 0, extremely unlikely)
        let id = NonZeroU64::new(val).unwrap_or(NonZeroU64::new(1).unwrap());
        
        CORE_ID.set(id).ok();

        unsafe {
            *out_handle = id.get();
        }

        Ok(())
    }));

    match result {
        Ok(Ok(())) => BridgeError::Ok as i32,
        Ok(Err(e)) => e as i32,
        Err(_) => BridgeError::CryptoFailure as i32,
    }
}

#[no_mangle]
pub extern "C" fn rcx_unlock_with_phrase(
    handle: u64,
    ptr: *const u8,
    len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if killed() || ptr.is_null() || len == 0 {
            return Err(BridgeError::InvalidInput);
        }

        // Validate Handle
        if CORE_ID.get().map(|id| id.get()) != Some(handle) {
            return Err(BridgeError::Denied);
        }

        let phrase = unsafe { core::slice::from_raw_parts(ptr, len) }.to_vec();

        CORE.get()
            .unwrap()
            .unlock_with_phrase(phrase)
            .map_err(BridgeError::from)
    }));

    match result {
        Ok(Ok(())) => BridgeError::Ok as i32,
        Ok(Err(e)) => e as i32,
        Err(_) => BridgeError::CryptoFailure as i32,
    }
}
