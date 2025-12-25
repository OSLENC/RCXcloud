use crate::bridge::api::CoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum BridgeError {
    Ok = 0,
    Locked = 1,
    Killed = 2,
    InvalidInput = 3,
    CryptoFailure = 4,
    IntegrityFailure = 5,
    Denied = 6,
}

// ✅ FIX: This trait impl is required for .map_err(BridgeError::from)
impl From<CoreError> for BridgeError {
    fn from(err: CoreError) -> Self {
        match err {
            CoreError::Locked => BridgeError::Locked,
            CoreError::Killed => BridgeError::Killed,
            CoreError::InvalidInput => BridgeError::InvalidInput,
            CoreError::CryptoFailure => BridgeError::CryptoFailure,
            CoreError::IntegrityFailure => BridgeError::IntegrityFailure,
            CoreError::Denied => BridgeError::Denied,
        }
    }
}
