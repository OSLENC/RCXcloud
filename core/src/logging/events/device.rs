//! APPEND-ONLY

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DeviceEvent {
    DeviceRegistered,
    DeviceRemoved,
    DeviceMarkedKilled,
}