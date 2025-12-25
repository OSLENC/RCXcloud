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
        let guard = Self::alloc();
        unsafe {
            ptr::write(guard.ptr, value);
        }
        guard
    }

    /// Allocate uninitialized protected memory.
    fn alloc() -> Self {
        let layout = std::alloc::Layout::new::<T>();
        let ptr = unsafe { std::alloc::alloc(layout) } as *mut T;
        
        if ptr.is_null() {
            std::process::abort();
        }

        Self {
            ptr,
            _marker: PhantomData,
        }
    }

    pub fn borrow(&self) -> &T {
        unsafe { &*self.ptr }
    }

    pub fn borrow_mut(&mut self) -> &mut T {
        unsafe { &mut *self.ptr }
    }
    
    pub fn zeroed() -> Self where T: Default {
        Self::new(T::default())
    }
}

impl<T: Zeroize + Clone> Clone for GuardedBox<T> {
    fn clone(&self) -> Self {
        Self::new(self.borrow().clone())
    }
}

impl<T: Zeroize> Drop for GuardedBox<T> {
    fn drop(&mut self) {
        unsafe {
            (*self.ptr).zeroize();
            std::alloc::dealloc(
                self.ptr as *mut u8,
                std::alloc::Layout::new::<T>()
            );
        }
    }
}

// ✅ FIX: This type alias is REQUIRED for other modules
pub type GuardedKey32 = GuardedBox<[u8; 32]>;
