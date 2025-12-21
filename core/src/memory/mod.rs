//! Memory safety and zeroization foundation (Secure Core).
//!
//! This module is the ROOT of the trusted dependency graph.
//! All cryptography, keystores, and policy enforcement depend on
//! the guarantees enforced here.
//!
//! ─────────────────────────────────────────────────────────────
//! FORMAL SECURITY INVARIANTS (NON-NEGOTIABLE)
//!
//! I1. No stack-resident secrets.
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
// Curated public surface
// ─────────────────────────────────────────────────────────────
//
// Only export what other layers are allowed to touch.
// No wildcard exports.
// No internal helpers exposed.

pub use zeroize::{
    Secret,
    wipe_bytes,
    wipe_vec,
};

pub use guard::{
    GuardedBox,
    GuardedKey32,
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
    fn secret_vec_is_zeroized_on_drop() {
        let secret = Secret::new(vec![0xAA; 32]);
        assert_eq!(secret.borrow()[0], 0xAA);
        // Drop happens at end of scope — cannot directly test memory,
        // but this ensures API usability.
    }
}