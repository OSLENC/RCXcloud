
//! Typed AEAD Associated Data (AAD).
//!
//! TRUST LEVEL: Secure Core
//!
//! FORMAL INVARIANTS (ENFORCED):
//! - AAD is STRUCTURED, not raw bytes
//! - All fields are fixed-width
//! - Serialization is deterministic
//! - Caller cannot omit security-critical context
//! - Used for BOTH encryption and decryption
//!
//! AAD is authenticated but NOT encrypted.

/// Associated data bound to each encrypted chunk.
///
/// This prevents:
/// - cross-file replay
/// - cross-cloud replay
/// - chunk reordering
/// - version downgrade attacks
#[derive(Clone, Copy)]
pub struct Aad {
    pub file_id: u64,
    pub chunk: u32,
    pub cloud_id: u16,
    pub version: u8,
}

impl Aad {
    /// Serialize AAD into a fixed-length byte array.
    ///
    /// Layout (15 bytes total):
    /// - [0..8]   file_id   (u64, BE)
    /// - [8..12]  chunk     (u32, BE)
    /// - [12..14] cloud_id  (u16, BE)
    /// - [14]     version   (u8)
    #[inline(always)]
    pub fn serialize(&self) -> [u8; 15] {
        let mut out = [0u8; 15];
        out[..8].copy_from_slice(&self.file_id.to_be_bytes());
        out[8..12].copy_from_slice(&self.chunk.to_be_bytes());
        out[12..14].copy_from_slice(&self.cloud_id.to_be_bytes());
        out[14] = self.version;
        out
    }
}
