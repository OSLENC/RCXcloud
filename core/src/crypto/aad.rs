//! NOTE:
//! This module MUST NOT be used for kill / recovery / control-plane AEAD.
//! Kill AAD is defined exclusively in `kill::protocol`.
//! Typed AEAD Associated Data (AAD).
//!
//! TRUST LEVEL: Secure Core
//!
//! FORMAL INVARIANTS:
//! - Structured, fixed-width
//! - Deterministic serialization
//! - Versioned
//! - Used ONLY for file encryption AEAD

/// Current supported AAD format version.
pub const AAD_VERSION_V1: u8 = 1;

#[derive(Clone, Copy)]
pub struct Aad {
    file_id: u64,
    chunk: u32,
    cloud_id: u16,
    version: u8,
}

impl Aad {
    #[inline(always)]
    pub fn new(
        file_id: u64,
        chunk: u32,
        cloud_id: u16,
        version: u8,
    ) -> Option<Self> {
        if version != AAD_VERSION_V1 {
            return None;
        }

        Some(Self {
            file_id,
            chunk,
            cloud_id,
            version,
        })
    }

    #[inline(always)]
    pub fn serialize(&self) -> [u8; 15] {
        let mut out = [0u8; 15];
        out[..8].copy_from_slice(&self.file_id.to_be_bytes());
        out[8..12].copy_from_slice(&self.chunk.to_be_bytes());
        out[12..14].copy_from_slice(&self.cloud_id.to_be_bytes());
        out[14] = self.version;
        out
    }

    #[inline(always)]
    pub fn file_id(&self) -> u64 { self.file_id }
    #[inline(always)]
    pub fn chunk(&self) -> u32 { self.chunk }
    #[inline(always)]
    pub fn cloud_id(&self) -> u16 { self.cloud_id }
    #[inline(always)]
    pub fn version(&self) -> u8 { self.version }
}
