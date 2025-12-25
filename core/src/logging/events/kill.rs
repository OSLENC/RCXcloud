
//! NON-AUTHORITATIVE

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KillEvent {
    KillRequested,
    KillVerified,
    KillExecuted,
}