
//! Sealed SHA-256 hashing (NON-SECRET).
//!
//! Hash outputs are NOT secrets.
//! They are integrity values and may be logged, compared, or stored.

use sha2::{Sha256, Digest};

/// Opaque hash output.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HashOutput([u8; 32]);

impl HashOutput {
    #[inline]
    pub fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for HashOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "HashOutput({:02x?})", &self.0[..])
    }
}

/// Compute SHA-256 hash.
///
/// SECURITY:
/// - No secrets involved
/// - Stack usage is acceptable
pub fn hash_sha256(data: &[u8]) -> HashOutput {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();

    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    HashOutput(buf)
}
