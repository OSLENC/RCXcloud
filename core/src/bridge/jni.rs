#![allow(unsafe_code)]
#![allow(non_snake_case)]

use crate::bridge::api::Core;
use crate::bridge::error::BridgeError;

use jni::objects::{JByteArray, JClass};
use jni::sys::{jbyteArray, jint, jlong};
use jni::JNIEnv;

use std::panic::{self, AssertUnwindSafe};
use std::sync::OnceLock;

const AEAD_TAG_LEN: usize = 16;
static CORE: OnceLock<Core> = OnceLock::new();

#[inline(always)]
fn core() -> &'static Core {
    CORE.get_or_init(Core::new)
}

#[inline(always)]
fn fail_null() -> jbyteArray {
    std::ptr::null_mut()
}

/* ───────────── EXPORTS ───────────── */

#[no_mangle]
pub extern "system" fn Java_com_rcxcloud_core_SecureCore_unlockWithPhrase(
    env: JNIEnv,
    _: JClass,
    phrase: JByteArray,
) -> jint {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let phrase = env
            .convert_byte_array(phrase)
            .map_err(|_| BridgeError::InvalidInput)?;

        core()
            .unlock_with_phrase(phrase)
            .map_err(|e| BridgeError::from(e))?;

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

#[no_mangle]
pub extern "system" fn Java_com_rcxcloud_core_SecureCore_encryptChunk(
    env: JNIEnv,
    _: JClass,
    file_id: jlong,
    cloud_id: jint,
    chunk: jint,
    plaintext: JByteArray,
) -> jbyteArray {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let data = env.convert_byte_array(plaintext).ok()?;
        let required_cap = data.len().checked_add(AEAD_TAG_LEN)?;
        let mut out = vec![0u8; required_cap];

        core()
            .encrypt_chunk(
                file_id as u64,
                cloud_id as u16,
                chunk as u32,
                &data,
                &mut out
            )
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
    env: JNIEnv,
    _: JClass,
    file_id: jlong,
    cloud_id: jint,
    chunk: jint,
    ciphertext: JByteArray,
) -> jbyteArray {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let data = env.convert_byte_array(ciphertext).ok()?;
        if data.len() < AEAD_TAG_LEN { return None; }
        
        let mut out = vec![0u8; data.len() - AEAD_TAG_LEN];

        let verified = core()
            .decrypt_chunk(
                file_id as u64,
                cloud_id as u16,
                chunk as u32,
                &data,
                &mut out
            )
            .ok()?;

        if !verified.0 { return None; }
        env.byte_array_from_slice(&out).ok()
    }));

    match result {
        Ok(Some(arr)) => arr.as_raw(),
        _ => fail_null(),
    }
}
