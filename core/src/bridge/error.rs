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
