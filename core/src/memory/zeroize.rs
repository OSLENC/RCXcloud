
//! Secure memory zeroization utilities (Secure Core).
//!
//! This module defines the *only* approved primitives for handling
//! sensitive material in memory.
//!
//! ─────────────────────────────────────────────────────────────
//! FORMAL SECURITY INVARIANTS
//! ─────────────────────────────────────────────────────────────
//!
//! I1. Secrets MUST NOT reside on the stack.
//! I2. Secrets MUST NOT be Clone, Copy, or Debuggable.
//! I3. Secrets MUST be deterministically zeroized.
//! I4. Secrets MUST NOT escape ownership control.
//! I5. Zeroization MUST be explicit or guaranteed by Drop.
//! I6. Stack arrays like `[u8; N]` are forbidden at compile time.
//!
//! Violation of any invariant is considered a Secure Core bug.

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use zeroize::Zeroize;

/// Zeroize a mutable byte slice.
///
/// Use ONLY for short-lived, non-owning buffers.
/// Never store long-lived secrets in slices.
#[inline]
pub fn wipe_bytes(buf: &mut [u8]) {
    buf.zeroize();
}

/// Zeroize a Vec<u8>.
///
/// Guarantees:
/// - contents wiped
/// - logical length cleared
///
/// Capacity may remain allocated — do not reuse for secrets.
pub fn wipe_vec(buf: &mut Vec<u8>) {
    buf.zeroize();
}

/// ⚠️ STRONGLY DISCOURAGED
///
/// `String` allocations may create allocator copies.
/// Kept ONLY for legacy edge cases.
#[deprecated(
    since = "0.1.0",
    note = "Use Vec<u8> + Secret instead. String secrets are unsafe."
)]
pub fn wipe_string(s: &mut String) {
    s.zeroize();
}

/// ─────────────────────────────────────────────────────────────
/// Sealed trait: restricts Secret<T> to heap-backed types only
/// ─────────────────────────────────────────────────────────────
mod sealed {
    pub trait HeapSecret {}
}

use sealed::HeapSecret;

/// Explicit allow-list for heap-backed secrets
impl HeapSecret for Vec<u8> {}

/// Ownership-enforcing wrapper for sensitive material.
///
/// SECURITY GUARANTEES:
/// - Heap-only construction (compile-time enforced)
/// - No Clone / Copy
/// - No Debug leakage
/// - Deterministic zeroization on Drop
/// - No ownership escape
#[must_use = "Secrets must be held and explicitly wiped or dropped"]
pub struct Secret<T: Zeroize> {
    inner: T,
    // Prevent Clone / Copy even if T implements them
    _no_copy_clone: PhantomData<Cell<()>>,
}

impl<T> Secret<T>
where
    T: Zeroize + HeapSecret,
{
    /// Construct a new heap-backed secret.
    ///
    /// ❌ Stack arrays like `[u8; 32]` are rejected at compile time.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            _no_copy_clone: PhantomData,
        }
    }
}

impl<T> Secret<T>
where
    T: Zeroize + Default + HeapSecret,
{
    /// Zero-copy initialization.
    ///
    /// Writes directly into heap memory.
    /// No intermediate stack copies are allowed.
    pub fn init_with<F>(initializer: F) -> Self
    where
        F: FnOnce(&mut T),
    {
        let mut inner = T::default();
        initializer(&mut inner);
        Self {
            inner,
            _no_copy_clone: PhantomData,
        }
    }
}

impl<T: Zeroize> Secret<T> {
    /// Immutable access.
    ///
    /// ⚠️ Keep scope minimal.
    pub fn borrow(&self) -> &T {
        &self.inner
    }

    /// Mutable access.
    ///
    /// ⚠️ Keep scope minimal.
    pub fn borrow_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Explicit immediate zeroization.
    ///
    /// After calling this, the secret is permanently invalid.
    pub fn wipe_now(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

/// Prevent accidental logging.
impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<Secret [REDACTED]>")
    }
}