//! Opaque, FFI-safe Core handle.
//!
//! SECURITY:
//! - No raw pointers exposed
//! - Kill-aware
//! - Non-forgeable
//! - Single-process only

use core::num::NonZeroU64;

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CoreHandle(NonZeroU64);

impl CoreHandle {
    pub(crate) fn new(id: NonZeroU64) -> Self {
        Self(id)
    }

    pub(crate) fn id(self) -> NonZeroU64 {
        self.0
    }
}






