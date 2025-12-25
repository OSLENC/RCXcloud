
//! Policy enforcement engine.
//!
//! TRUST LEVEL: Secure Core
//!
//! FINAL AUTHORITY ON:
//! - Permission checks
//! - Kill authorization (NOT execution)
//!
//! SECURITY INVARIANTS:
//! - Kill overrides ALL permissions
//! - No soft kill
//! - No re-unlock after kill
//! - Kill is process-lifetime irreversible
//! - Policy NEVER orchestrates kill mechanics

use crate::policy::capability::Capability;
use crate::device::registry::DeviceRegistry;
use crate::kill;
use crate::kill::GLOBAL_KILLED;
use core::sync::atomic::Ordering;

/* ───────────── OPERATIONS ───────────── */

/// High-level operations gated by policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Upload,
    Download,
    Restore,
    Route,
    ViewStatus,
    RegisterDevice,
    RemoveDevice,
    IssueKill,
}

/* ───────────── CAPABILITY SET ───────────── */

/// Read-only capability set (application supplied).
///
/// SECURITY:
/// - Immutable
/// - Non-owning
/// - Cannot be escalated
pub struct CapabilitySet {
    caps: &'static [Capability],
}

impl CapabilitySet {
    pub const fn new(caps: &'static [Capability]) -> Self {
        Self { caps }
    }

    #[inline(always)]
    pub fn allows(&self, cap: Capability) -> bool {
        self.caps.iter().any(|c| *c == cap)
    }
}

/* ───────────── POLICY ENFORCER ───────────── */

/// Central policy enforcement authority.
///
/// SECURITY:
/// - No cryptography
/// - No key access
/// - Kill delegation ONLY
pub struct PolicyEnforcer<'a> {
    registry: &'a DeviceRegistry,
    caps: CapabilitySet,
}

impl<'a> PolicyEnforcer<'a> {
    pub fn new(
        registry: &'a DeviceRegistry,
        caps: CapabilitySet,
    ) -> Self {
        Self {
            registry,
            caps,
        }
    }

    /* ───────────── PERMISSION CHECK ───────────── */

    /// Check whether an operation is allowed.
    ///
    /// SECURITY:
    /// - Kill state overrides ALL permissions
    /// - Fail-closed
    pub fn allow(&self, op: Operation) -> bool {
        if GLOBAL_KILLED.load(Ordering::SeqCst) || self.registry.is_killed() {
            return false;
        }

        match op {
            Operation::Upload         => self.caps.allows(Capability::Upload),
            Operation::Download       => self.caps.allows(Capability::Download),
            Operation::Restore        => self.caps.allows(Capability::Restore),
            Operation::Route          => self.caps.allows(Capability::RouteContent),
            Operation::ViewStatus     => self.caps.allows(Capability::ViewStatus),
            Operation::RegisterDevice => self.caps.allows(Capability::RegisterDevice),
            Operation::RemoveDevice   => self.caps.allows(Capability::RemoveDevice),
            Operation::IssueKill      => self.caps.allows(Capability::IssueKill),
        }
    }

    /* ───────────── HARD KILL ───────────── */

    /// Execute an irreversible device kill.
    ///
    /// SECURITY:
    /// - Authorization handled here
    /// - Execution delegated to kill subsystem
    /// - NEVER RETURNS
    pub fn execute_kill(&self, reason: &str) -> ! {
        // Authorization check (fail closed)
        if !self.allow(Operation::IssueKill) {
            // Unauthorized kill attempt → immediate local kill
            kill::execute_kill("unauthorized kill attempt");
        }

        // Delegate full execution
        kill::execute_kill(reason)
    }
}