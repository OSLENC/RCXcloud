pub mod cloud;
pub mod session;
pub mod workflow;

// Application emits events, core handles logging/encryption
pub trait AppEvent {
    fn event_name(&self) -> &'static str;
}
