//! Secure memory zeroization utilities (Secure Core).
//!
//! THIS MODULE IS A TRUST ANCHOR.
//!
//! ─────────────────────────────────────────────────────────────
//! FORMAL SECURITY INVARIANTS (ENFORCED)
//!
//! I1. Secret CONTENTS must NEVER exist on the stack
//! I2. Secrets MUST be heap-only
//! I3. Deterministic zeroization (Drop or explicit)
//! I4. No Clone / Copy / Debug leakage
//! I5. Ownership is linear and consuming
//! I6. Wiped secrets are permanently invalid
//!
//! Violation of any invariant is a Secure Core bug.

#![deny(clippy::derive_debug)]

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use zeroize::Zeroize;

/* ───────────── LOW-LEVEL WIPE HELPERS ───────────── */

/// Zeroize a transient byte slice.
///
/// SECURITY:
/// - Use ONLY for short-lived, non-owning buffers
#[inline]
pub fn wipe_bytes(buf: &mut [u8]) {
    buf.zeroize();
}

/// Zeroize and clear a transient Vec<u8>.
///
/// SECURITY:
/// - Capacity may remain allocated
/// - MUST NOT be reused for secrets
pub fn wipe_vec(buf: &mut Vec<u8>) {
    buf.zeroize();
    buf.clear();
}

/* ───────────── SEALED HEAP-ONLY TRAIT ───────────── */

mod sealed {
    pub trait HeapOnly {}
}

use sealed::HeapOnly;

/// Explicit allow-list: heap-backed only
impl HeapOnly for Vec<u8> {}

/* ───────────── SECRET TYPE ───────────── */

/// Ownership-enforcing wrapper for sensitive heap material.
///
/// SECURITY GUARANTEES:
/// - Heap-backed only
/// - Deterministic zeroization
/// - Linear ownership
/// - No Clone / Copy / Debug
#[must_use = "Secrets must be explicitly held or dropped"]
pub struct Secret<T: Zeroize + HeapOnly> {
    inner: Option<Box<T>>,
    _no_clone_copy: PhantomData<Cell<()>>,
}

impl<T> Secret<T>
where
    T: Zeroize + HeapOnly + Default,
{
    /// Take ownership of heap-backed secret material.
    pub fn new(value: T) -> Self {
        Self {
            inner: Some(Box::new(value)),
            _no_clone_copy: PhantomData,
        }
    }

    /// Heap-first initialization.
    ///
    /// SECURITY:
    /// - Allocation occurs BEFORE initialization
    /// - No stack-resident secret bytes
    pub fn init_with<F>(init: F) -> Self
    where
        F: FnOnce(&mut T),
    {
        let mut boxed = Box::new(T::default());
        init(&mut boxed);

        Self {
            inner: Some(boxed),
            _no_clone_copy: PhantomData,
        }
    }

    /// Immutable borrow — KEEP SCOPE MINIMAL.
    #[inline(always)]
    pub fn borrow(&self) -> &T {
        self.inner
            .as_deref()
            .expect("Secret already wiped or consumed")
    }

    /// Mutable borrow — KEEP SCOPE MINIMAL.
    #[inline(always)]
    pub fn borrow_mut(&mut self) -> &mut T {
        self.inner
            .as_deref_mut()
            .expect("Secret already wiped or consumed")
    }

    /// Explicit irreversible wipe.
    ///
    /// After this call, the secret is permanently invalid.
    pub fn wipe_now(&mut self) {
        if let Some(mut boxed) = self.inner.take() {
            boxed.zeroize();
        }
    }
}

impl<T: Zeroize + HeapOnly> Drop for Secret<T> {
    fn drop(&mut self) {
        if let Some(mut boxed) = self.inner.take() {
            boxed.zeroize();
        }
    }
}

/// Prevent accidental logging.
impl<T: Zeroize + HeapOnly> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<Secret [REDACTED]>")
    }
}



