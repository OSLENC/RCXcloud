//! Android JNI adapter (THIN, SAFE).
//!
//! SECURITY:
//! - Panic-safe (never crash JVM)
//! - Fail-closed on all errors
//! - No secret material escapes

#![allow(non_snake_case)]

use crate::bridge::api::Core;
use crate::bridge::error::BridgeError;

use jni::objects::{JByteArray, JClass};
use jni::sys::{jbyteArray, jint, jlong};
use jni::JNIEnv;

use std::panic::{self, AssertUnwindSafe};
use std::sync::OnceLock;

/* ───────────── CONSTANTS ───────────── */

/// AES-GCM authentication tag length (bytes).
/// WARNING: Java buffers MUST account for this overhead.
/// Encrypt Out = In + 16
/// Decrypt Out = In - 16
const AEAD_TAG_LEN: usize = 16;

/* ───────────── SINGLETON ───────────── */

static CORE: OnceLock<Core> = OnceLock::new();

#[inline(always)]
fn core() -> &'static Core {
    CORE.get_or_init(Core::new)
}

/* ───────────── HELPERS ───────────── */

#[inline(always)]
fn fail_null() -> jbyteArray {
    std::ptr::null_mut()
}

#[inline(always)]
fn throw_bridge_error(env: &mut JNIEnv, err: BridgeError) {
    // Simplified error thrower
    let msg = format!("SecureCore Error: {:?}", err);
    let _ = env.throw_new("java/lang/SecurityException", msg);
}

/* ───────────── LIFECYCLE ───────────── */

#[no_mangle]
pub extern "system" fn Java_com_rcxcloud_core_SecureCore_unlockWithPhrase(
    mut env: JNIEnv,
    _: JClass,
    phrase: JByteArray,
) -> jint {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let phrase = env
            .convert_byte_array(phrase)
            .map_err(|_| BridgeError::InvalidInput)?;

        core()
            .unlock_with_phrase(phrase)
            .map_err(BridgeError::from)?;

        Ok(())
    }));

    match result {
        Ok(Ok(())) => BridgeError::Ok as jint,
        Ok(Err(e)) => e as jint,
        Err(_) => BridgeError::CryptoFailure as jint,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_rcxcloud_core_SecureCore_lock(
    _: JNIEnv,
    _: JClass,
) {
    let _ = panic::catch_unwind(|| {
        core().lock();
    });
}

#[no_mangle]
pub extern "system" fn Java_com_rcxcloud_core_SecureCore_isKilled(
    _: JNIEnv,
    _: JClass,
) -> jint {
    let result = panic::catch_unwind(|| core().is_killed());
    match result {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => 1, // fail-closed
    }
}

/* ───────────── FILE ENCRYPTION ───────────── */

#[no_mangle]
pub extern "system" fn Java_com_rcxcloud_core_SecureCore_encryptChunk(
    mut env: JNIEnv,
    _: JClass,
    file_id: jlong,
    cloud_id: jint,
    chunk: jint,
    plaintext: JByteArray,
) -> jbyteArray {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let data = env.convert_byte_array(plaintext).ok()?;

        let cloud_id = u16::try_from(cloud_id).ok()?;
        let chunk = u32::try_from(chunk).ok()?;
        let file_id = u64::try_from(file_id).ok()?;

        // ✅ Check for integer overflow on allocation
        let required_cap = data.len().checked_add(AEAD_TAG_LEN)?;
        let mut out = vec![0u8; required_cap];

        core()
            .encrypt_chunk(file_id, cloud_id, chunk, &data, &mut out)
            .ok()?;

        env.byte_array_from_slice(&out).ok()
    }));

    match result {
        Ok(Some(arr)) => arr.as_raw(),
        _ => fail_null(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_rcxcloud_core_SecureCore_decryptChunk(
    mut env: JNIEnv,
    _: JClass,
    file_id: jlong,
    cloud_id: jint,
    chunk: jint,
    ciphertext: JByteArray,
) -> jbyteArray {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let data = env.convert_byte_array(ciphertext).ok()?;
        if data.len() < AEAD_TAG_LEN {
            return None;
        }

        let cloud_id = u16::try_from(cloud_id).ok()?;
        let chunk = u32::try_from(chunk).ok()?;
        let file_id = u64::try_from(file_id).ok()?;

        let mut out = vec![0u8; data.len() - AEAD_TAG_LEN];

        let verified = core()
            .decrypt_chunk(file_id, cloud_id, chunk, &data, &mut out)
            .ok()?;

        if !verified.0 {
            out.fill(0);
            return None;
        }

        env.byte_array_from_slice(&out).ok()
    }));

    match result {
        Ok(Some(arr)) => arr.as_raw(),
        _ => fail_null(),
    }
}

