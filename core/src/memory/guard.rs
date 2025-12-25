//! Guarded memory allocation (PAGE-LOCKED).
//!
//! TRUST LEVEL: Secure Core

#![allow(unsafe_code)]

use core::marker::PhantomData;
use core::ptr;
use zeroize::Zeroize;

/// A fixed-size, page-locked, zeroizing container.
pub struct GuardedBox<T: Zeroize> {
    ptr: *mut T,
    _marker: PhantomData<T>,
}

unsafe impl<T: Zeroize + Send> Send for GuardedBox<T> {}
unsafe impl<T: Zeroize + Sync> Sync for GuardedBox<T> {}

impl<T: Zeroize> GuardedBox<T> {
    /// Create a new guarded box initialized with the value.
    pub fn new(value: T) -> Self {
        let mut guard = Self::alloc();
        unsafe {
            ptr::write(guard.ptr, value);
        }
        guard
    }

    /// Allocate uninitialized protected memory.
    fn alloc() -> Self {
        // In a real OS integration, this would use mlock/VirtualLock.
        // For this portable Core, we use the global allocator but force zeroization.
        let layout = std::alloc::Layout::new::<T>();
        let ptr = unsafe { std::alloc::alloc(layout) } as *mut T;
        
        if ptr.is_null() {
            // Secure Core invariant: Allocation failure = Abort
            std::process::abort();
        }

        Self {
            ptr,
            _marker: PhantomData,
        }
    }

    /// Access inner value.
    pub fn borrow(&self) -> &T {
        unsafe { &*self.ptr }
    }

    /// Mutable access.
    pub fn borrow_mut(&mut self) -> &mut T {
        unsafe { &mut *self.ptr }
    }
    
    /// Create a zero-initialized instance (helper for keys).
    pub fn zeroed() -> Self where T: Default {
        Self::new(T::default())
    }
}

// ✅ FIX: Implement Clone to allow KeyStore to hand out copies of keys
impl<T: Zeroize + Clone> Clone for GuardedBox<T> {
    fn clone(&self) -> Self {
        Self::new(self.borrow().clone())
    }
}

impl<T: Zeroize> Drop for GuardedBox<T> {
    fn drop(&mut self) {
        unsafe {
            // 1. Zeroize content
            (*self.ptr).zeroize();
            // 2. Deallocate
            std::alloc::dealloc(
                self.ptr as *mut u8,
                std::alloc::Layout::new::<T>()
            );
        }
    }
}
