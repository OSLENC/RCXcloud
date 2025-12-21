
// core/src/policy/enforcement.rs

//! Policy enforcement engine.
//!
//! This module is the FINAL authority on:
//! - whether an operation is allowed
//! - whether a device is locked or killed
//! - when irreversible actions are executed
//!
//! SECURITY INVARIANTS:
//! - No soft kill
//! - No re-unlock after kill
//! - Kill invalidates device identity permanently
//! - Enforcement is synchronous and fail-closed

use crate::policy::capability::*;
use crate::keystore::KeyStore;
use crate::device::registry::DeviceRegistry;
use crate::kill::executor::KillExecutor;

/// High-level operations gated by policy.
#[derive(Debug, Clone, Copy)]
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

/// Central policy enforcer.
pub struct PolicyEnforcer<'a> {
    keystore: &'a KeyStore,
    registry: &'a DeviceRegistry,
    kill_exec: &'a KillExecutor,
}

impl<'a> PolicyEnforcer<'a> {
    pub fn new(
        keystore: &'a KeyStore,
        registry: &'a DeviceRegistry,
        kill_exec: &'a KillExecutor,
    ) -> Self {
        Self {
            keystore,
            registry,
            kill_exec,
        }
    }

    /// Resolve capabilities for *this device*.
    ///
    /// IMPORTANT:
    /// - A killed device ALWAYS resolves to CAPS_LOCKED
    /// - Admin is a superset, never a downgrade
    pub fn resolve_caps(&self) -> &'static CapabilitySet {
        if self.registry.is_this_device_killed() {
            return &CAPS_LOCKED;
        }

        if self.registry.is_this_device_admin() {
            return &CAPS_ADMIN;
        }

        &CAPS_STANDARD
    }

    /// Check whether an operation is allowed.
    pub fn allow(&self, op: Operation) -> bool {
        let caps = self.resolve_caps();

        match op {
            Operation::Upload =>
                caps.allows(Capability::Upload),

            Operation::Download =>
                caps.allows(Capability::Download),

            Operation::Restore =>
                caps.allows(Capability::Restore),

            Operation::Route =>
                caps.allows(Capability::RouteContent),

            Operation::ViewStatus =>
                caps.allows(Capability::ViewStatus),

            Operation::RegisterDevice =>
                caps.allows(Capability::RegisterDevice),

            Operation::RemoveDevice =>
                caps.allows(Capability::RemoveDevice),

            Operation::IssueKill =>
                caps.allows(Capability::IssueKill),
        }
    }

    /* ======================
       HARD KILL ENFORCEMENT
       ====================== */

    /// Execute a remote or local kill instruction.
    ///
    /// THIS IS NOT A SOFT KILL.
    /// THIS CANNOT BE UNDONE.
    pub fn execute_kill(&self, reason: &str) -> ! {
        // 1️⃣ Immediately acknowledge execution start (before wipe)
        self.kill_exec.notify_execution_started(reason);

        // 2️⃣ Invalidate device in registry (persistent, encrypted)
        self.registry.mark_this_device_killed();

        // 3️⃣ Wipe all keys (session + root)
        self.keystore.lock();

        // 4️⃣ Execute irreversible kill sequence
        self.kill_exec.execute_final();

        // 5️⃣ Never return
        unreachable!("Killed device must never resume execution");
    }
}

