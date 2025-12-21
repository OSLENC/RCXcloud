
// core/src/policy/capability.rs

//! Capability definitions for RCXCloud.
//!
//! Capabilities are *permissions*, not roles.
//! They describe WHAT a device or workflow may do,
//! never HOW it is done.
//!
//! SECURITY INVARIANTS:
//! - No implicit privileges
//! - Admin is a superset, not a special case
//! - Capabilities are additive, never subtractive
//! - Capabilities are evaluated by the policy engine only

use core::fmt;

/// Atomic permissions understood by the Secure Core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    // ---- Cloud & Data ----
    Encrypt,
    Decrypt,
    Upload,
    Download,
    Restore,
    ViewStatus,

    // ---- Routing & Policy ----
    RouteContent,
    ModifyPolicy,

    // ---- Device Management ----
    RegisterDevice,
    RemoveDevice,
    RenameDevice,

    // ---- Kill & Recovery ----
    IssueKill,
    ExecuteKill, // only local device may execute its own kill

    // ---- Diagnostics ----
    ViewLogs,
}

/// A resolved, immutable capability set.
#[derive(Clone)]
pub struct CapabilitySet {
    caps: &'static [Capability],
}

impl CapabilitySet {
    pub const fn new(caps: &'static [Capability]) -> Self {
        Self { caps }
    }

    #[inline]
    pub fn allows(&self, cap: Capability) -> bool {
        self.caps.contains(&cap)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Capability> {
        self.caps.iter()
    }
}

impl fmt::Debug for CapabilitySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.caps.iter()).finish()
    }
}

/* =========================
   Canonical Capability Sets
   ========================= */

// Regular working device
pub static CAPS_STANDARD: CapabilitySet = CapabilitySet::new(&[
    Capability::Encrypt,
    Capability::Decrypt,
    Capability::Upload,
    Capability::Download,
    Capability::Restore,
    Capability::ViewStatus,
    Capability::RouteContent,
]);

// Admin device (superset, NOT crippled)
pub static CAPS_ADMIN: CapabilitySet = CapabilitySet::new(&[
    // Standard
    Capability::Encrypt,
    Capability::Decrypt,
    Capability::Upload,
    Capability::Download,
    Capability::Restore,
    Capability::ViewStatus,
    Capability::RouteContent,

    // Admin powers
    Capability::ModifyPolicy,
    Capability::RegisterDevice,
    Capability::RemoveDevice,
    Capability::RenameDevice,
    Capability::IssueKill,
]);

// Killed / locked device
pub static CAPS_LOCKED: CapabilitySet = CapabilitySet::new(&[]);
