// Event-only logging interface.
// No crypto, no persistence, no secrets.
// Secure Core owns encryption separately.

#[derive(Debug, Clone)]
pub enum CoreEvent {
    Startup,
    Shutdown,
    Lock,
    Unlock,
    IntegrityFailure,
    RemoteWipeTriggered,
    PolicyViolation,
}

pub trait EventSink {
    fn emit(event: CoreEvent);
}
