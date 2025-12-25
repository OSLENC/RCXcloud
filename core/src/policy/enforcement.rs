//! Policy enforcement engine.
//!
//! TRUST LEVEL: Secure Core

use crate::policy::capability::Capability;
use crate::device::registry::DeviceRegistry;
use crate::keystore::master::GLOBAL_KILLED; // ✅ FIX: Correct import
use core::sync::atomic::Ordering;

/* ───────────── OPERATIONS ───────────── */

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

    pub fn allow(&self, op: Operation) -> bool {
        // Kill state overrides ALL permissions
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

    // ✅ NOTE: execute_kill was removed. 
    // The Bridge is responsible for calling kill::execute_kill()
    // ONLY IF policy.allow(Operation::IssueKill) returns true.
}
