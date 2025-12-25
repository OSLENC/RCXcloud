//! Capability definitions (Policy Layer).
//!
//! TRUST LEVEL: Policy
//!
//! Capabilities are declarative permissions supplied by
//! the application layer. They do NOT imply authority
//! unless enforced by the Secure Core.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /* ───── Cloud & Data ───── */
    Encrypt,
    Decrypt,
    Upload,
    Download,
    Restore,
    ViewStatus,

    /* ───── Encryption Strategy ───── */
    UseStrategyB,
    ExportRecovery,
    ImportRecovery,
    DisableRecovery,

    /* ───── Routing & Policy ───── */
    RouteContent,
    ModifyPolicy,

    /* ───── Device Management ───── */
    RegisterDevice,
    RemoveDevice,
    RenameDevice,

    /* ───── Kill & Recovery ───── */
    IssueKill,

    /* ───── Diagnostics ───── */
    ViewLogs,
}