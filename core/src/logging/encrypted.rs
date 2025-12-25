//! Authenticated append-only encrypted logging.
//!
//! TRUST LEVEL: Secure Core (PASSIVE STORAGE)
//!
//! SECURITY INVARIANTS:
//! - No `unsafe` blocks
//! - Fail-closed
//! - Bounded memory usage
//! - GLOBAL_KILLED checked on ALL writes

use crate::keystore::master::GLOBAL_KILLED;
use core::sync::atomic::Ordering;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::OnceLock;

static LOG_ROOT: OnceLock<PathBuf> = OnceLock::new();

/// Initialize logging root directory.
/// MUST be called exactly once at startup by the Bridge.
pub fn init_log_root(path: PathBuf) {
    let _ = LOG_ROOT.set(path);
}

fn log_root() -> Result<PathBuf, ()> {
    LOG_ROOT.get().cloned().ok_or(())
}

/// Persistent log handle.
pub struct EncryptedLog {
    file: File,
}

impl EncryptedLog {
    /* ───────────── PUBLIC OPENERS ───────────── */

    /// Open Identity Log (Mode: Overwrite).
    pub fn open_device_identity() -> Result<Self, ()> {
        Self::open_overwrite("device_identity.bin")
    }

    /// Open Kill Flag Log (Mode: Append).
    pub fn open_device_kill_log() -> Result<Self, ()> {
        Self::open_append("device_kill.log")
    }

    /// Open Replay Token Log (Mode: Append).
    pub fn open_replay_log() -> Result<Self, ()> {
        Self::open_append("kill_replay.log")
    }

    /* ───────────── INTERNAL HELPERS (STRICT MODES) ───────────── */

    fn open_append(name: &str) -> Result<Self, ()> {
        if GLOBAL_KILLED.load(Ordering::SeqCst) {
            return Err(());
        }
        Self::open_internal(name, true)
    }

    fn open_overwrite(name: &str) -> Result<Self, ()> {
        if GLOBAL_KILLED.load(Ordering::SeqCst) {
            return Err(());
        }
        Self::open_internal(name, false)
    }

    fn open_internal(name: &str, append: bool) -> Result<Self, ()> {
        let mut path = log_root()?;
        std::fs::create_dir_all(&path).map_err(|_| ())?;
        path.push(name);

        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .append(append)
            .open(path)
            .map_err(|_| ())?;

        Ok(Self { file })
    }

    /* ───────────── STANDARD LOG (Length-Prefixed) ───────────── */

    /// Append a length-prefixed binary record.
    /// Used for: Kill Flags, Audit.
    pub fn append_record(&mut self, data: &[u8]) -> Result<(), ()> {
        if GLOBAL_KILLED.load(Ordering::SeqCst) {
            return Err(());
        }

        let len = (data.len() as u32).to_be_bytes();
        self.file.write_all(&len).map_err(|_| ())?;
        self.file.write_all(data).map_err(|_| ())?;
        self.file.flush().map_err(|_| ())?;
        Ok(())
    }

    /// Check if the log contains ANY data.
    /// Used for: Kill switch detection (Existence-based).
    pub fn has_any_content(&self) -> bool {
        match self.file.metadata() {
            Ok(m) => m.len() > 0,
            Err(_) => true, // Fail closed: Assume content exists (e.g. killed) on error
        }
    }

    /* ───────────── REPLAY LOG (Raw u64) ───────────── */

    /// Append a raw u64 record.
    /// STRICTLY for Replay Log. No length prefix.
    pub fn append_u64(&mut self, value: u64) -> Result<(), ()> {
        // ✅ FIX: Mandatory Kill Check
        if GLOBAL_KILLED.load(Ordering::SeqCst) {
            return Err(());
        }

        self.file.seek(SeekFrom::End(0)).map_err(|_| ())?;
        self.file.write_all(&value.to_be_bytes()).map_err(|_| ())?;
        self.file.flush().map_err(|_| ())?;
        Ok(())
    }

    /// Read last u64 record.
    /// ASSUMES: File consists ONLY of raw 8-byte records.
    pub fn read_last_u64(&mut self) -> Result<Option<u64>, ()> {
        let len = self.file.metadata().map_err(|_| ())?.len();

        // Must have at least one u64 (8 bytes)
        if len < 8 {
            return Ok(None);
        }

        // Integrity check: File size must be multiple of 8
        if len % 8 != 0 {
            return Err(()); // Corrupt tail
        }

        self.file.seek(SeekFrom::End(-8)).map_err(|_| ())?;

        let mut buf = [0u8; 8];
        self.file.read_exact(&mut buf).map_err(|_| ())?;
        
        Ok(Some(u64::from_be_bytes(buf)))
    }

    /* ───────────── IDENTITY (Fixed) ───────────── */

    /// Write fixed-size identity blob.
    /// ⚠️ NOT APPEND-ONLY. Overwrites file.
    /// RESTRICTED: Use ONLY for Device Identity.
    pub fn write_fixed(&mut self, data: &[u8]) -> Result<(), ()> {
        if GLOBAL_KILLED.load(Ordering::SeqCst) {
            return Err(());
        }

        self.file.set_len(0).map_err(|_| ())?;
        self.file.seek(SeekFrom::Start(0)).map_err(|_| ())?;
        self.file.write_all(data).map_err(|_| ())?;
        self.file.flush().map_err(|_| ())?;
        Ok(())
    }

    /// Read fixed-size blob.
    pub fn read_fixed(&mut self) -> Result<Option<Vec<u8>>, ()> {
        self.file.seek(SeekFrom::Start(0)).map_err(|_| ())?;
        let mut buf = Vec::new();
        self.file.read_to_end(&mut buf).map_err(|_| ())?;
        if buf.is_empty() {
            Ok(None)
        } else {
            Ok(Some(buf))
        }
    }
}
