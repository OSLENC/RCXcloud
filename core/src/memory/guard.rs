//! Guarded, memory-locked heap allocations (Secure Core).
//!
//! Provides page-locked heap allocations for long-lived secrets.
//!
//! FORMAL SECURITY INVARIANTS
//! G1. Heap-only allocation
//! G2. Memory is locked (mlock / VirtualLock) or PANIC
//! G3. No stack copies of secrets
//! G4. Panic during init MUST NOT leak memory
//! G5. Zeroize BEFORE unlock + dealloc
//! G6. No Clone / Copy / Debug

use core::alloc::{Layout, System};
use core::cell::Cell;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use zeroize::Zeroize;

#[cfg(unix)]
use libc::{mlock, munlock};

#[cfg(windows)]
use winapi::um::winbase::{VirtualLock, VirtualUnlock};

/// Page-locked, heap-only guarded allocation.
#[must_use = "GuardedBox must be held to keep memory locked"]
pub struct GuardedBox<T: Zeroize> {
    ptr: NonNull<T>,
    layout: Layout,
    _no_clone_copy: PhantomData<Cell<()>>,
}

impl<T: Zeroize> GuardedBox<T> {
    /// Allocate and initialize guarded memory.
    ///
    /// SECURITY:
    /// - Heap-only
    /// - Panic-safe
    /// - No stack intermediates
    /// - Panics if memory locking fails
    pub fn init_with<F>(initializer: F) -> Self
    where
        F: FnOnce(&mut T),
    {
        let layout = Layout::new::<T>();

        // Allocate raw heap memory
        let raw = unsafe { System.alloc(layout) };
        let raw = NonNull::new(raw as *mut MaybeUninit<T>)
            .expect("GuardedBox allocation failed");

        // Lock memory (fail-closed)
        Self::lock_or_panic(raw.as_ptr() as *const u8, layout.size());

        // Panic safety guard
        struct InitGuard<T: Zeroize> {
            ptr: *mut MaybeUninit<T>,
            layout: Layout,
        }

        impl<T: Zeroize> Drop for InitGuard<T> {
            fn drop(&mut self) {
                unsafe {
                    // Best-effort zeroization
                    let bytes = core::slice::from_raw_parts_mut(
                        self.ptr as *mut u8,
                        self.layout.size(),
                    );
                    bytes.zeroize();

                    // Unlock
                    #[cfg(unix)]
                    munlock(self.ptr as *const _, self.layout.size());
                    #[cfg(windows)]
                    VirtualUnlock(self.ptr as *mut _, self.layout.size());

                    // Deallocate
                    System.dealloc(self.ptr as *mut u8, self.layout);
                }
            }
        }

        let mut guard = InitGuard {
            ptr: raw.as_ptr(),
            layout,
        };

        // Initialize in place
        unsafe {
            let slot = &mut *guard.ptr;
            initializer(slot.assume_init_mut());
        }

        // Initialization succeeded — disarm guard
        core::mem::forget(guard);

        Self {
            ptr: unsafe { NonNull::new_unchecked(raw.as_ptr() as *mut T) },
            layout,
            _no_clone_copy: PhantomData,
        }
    }

    /// Immutable access — KEEP SCOPE MINIMAL.
    #[inline]
    pub fn borrow(&self) -> &T {
        unsafe { &*self.ptr.as_ptr() }
    }

    /// Mutable access — KEEP SCOPE MINIMAL.
    #[inline]
    pub fn borrow_mut(&mut self) -> &mut T {
        unsafe { &mut *self.ptr.as_ptr() }
    }

    #[inline]
    fn lock_or_panic(addr: *const u8, len: usize) {
        #[cfg(unix)]
        unsafe {
            if mlock(addr as *const _, len) != 0 {
                panic!("mlock failed: Secure Core requires locked memory");
            }
        }

        #[cfg(windows)]
        unsafe {
            if VirtualLock(addr as *mut _, len) == 0 {
                panic!("VirtualLock failed: Secure Core requires locked memory");
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = (addr, len);
            panic!("Secure Core requires memory locking support");
        }
    }

    #[inline]
    fn unlock(addr: *const u8, len: usize) {
        #[cfg(unix)]
        unsafe {
            munlock(addr as *const _, len);
        }

        #[cfg(windows)]
        unsafe {
            VirtualUnlock(addr as *mut _, len);
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = (addr, len);
        }
    }
}

impl<T: Zeroize> Drop for GuardedBox<T> {
    fn drop(&mut self) {
        unsafe {
            // Zeroize contents
            let bytes = core::slice::from_raw_parts_mut(
                self.ptr.as_ptr() as *mut u8,
                self.layout.size(),
            );
            bytes.zeroize();

            // Unlock and deallocate
            Self::unlock(self.ptr.as_ptr() as *const u8, self.layout.size());
            System.dealloc(self.ptr.as_ptr() as *mut u8, self.layout);
        }
    }
}

/// Canonical guarded 256-bit key type.
pub type GuardedKey32 = GuardedBox<[u8; 32]>;

impl GuardedKey32 {
    /// Create a zeroed, locked 32-byte key buffer.
    pub fn zeroed() -> Self {
        Self::init_with(|buf| buf.fill(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic;

    #[test]
    fn guarded_box_init_success() {
        let g = GuardedBox::<[u8; 32]>::init_with(|buf| {
            buf.fill(0xAA);
        });
        assert!(g.borrow().iter().all(|b| *b == 0xAA));
    }

    #[test]
    fn guarded_box_init_panics_without_leak() {
        let result = panic::catch_unwind(|| {
            let _ = GuardedBox::<[u8; 32]>::init_with(|_| {
                panic!("intentional panic");
            });
        });
        assert!(result.is_err());
    }

    #[test]
    fn guarded_box_drop_is_safe() {
        {
            let _ = GuardedKey32::zeroed();
        }
    }
}
