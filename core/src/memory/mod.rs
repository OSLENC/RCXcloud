//! Memory safety and zeroization foundation (Secure Core).
//!
//! This module is the ROOT of the trusted dependency graph.
//! All cryptography, keystores, policy enforcement, and media
//! pipelines depend on the guarantees enforced here.
//!
//! ─────────────────────────────────────────────────────────────
//! FORMAL SECURITY INVARIANTS (NON-NEGOTIABLE)
//!
//! I1. Secret CONTENTS must never reside on the stack
//!     (handles / pointers are permitted).
//! I2. All secret material MUST be heap-allocated.
//! I3. All secret material MUST be deterministically zeroized.
//! I4. Long-lived secrets MUST reside in locked memory.
//! I5. Clone / Copy of secrets MUST be impossible.
//! I6. Public APIs MUST NOT expose unsafe memory access.
//! I7. Failure MUST leave memory in a safe, wiped state.
//!
//! Any violation of these invariants is a SECURITY BUG.
//! ─────────────────────────────────────────────────────────────

pub mod zeroize;
pub mod guard;

// ─────────────────────────────────────────────────────────────
// Curated public surface (EXPLICIT EXPORTS ONLY)
// ─────────────────────────────────────────────────────────────
//
// RULES:
// - No wildcard exports
// - No stack-backed secret types
// - No raw pointers
// - No unsafe memory exposure

// ───── Zeroization utilities (short-lived, non-owning) ─────
pub use zeroize::{
    Secret,      // Heap-backed, ownership-enforced secret
    wipe_bytes, // For transient buffers only
    wipe_vec,   // For transient Vec<u8> buffers only
};

// ───── Guarded allocations (long-lived, locked memory) ─────
pub use guard::{
    GuardedBox,    // Page-locked heap allocation
    GuardedKey32, // Canonical 256-bit secret key
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guarded_key32_is_zeroed_on_init() {
        let key = GuardedKey32::zeroed();
        assert!(key.borrow().iter().all(|b| *b == 0));
    }

    #[test]
    fn secret_vec_is_accessible_and_scoped() {
        let secret = Secret::new(vec![0xAA; 32]);
        assert_eq!(secret.borrow()[0], 0xAA);
        // Drop occurs at end of scope; zeroization is guaranteed by Drop.
    }
}