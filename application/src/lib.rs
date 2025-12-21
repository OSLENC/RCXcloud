pub mod cloud;
pub mod workflow;
pub mod session;

// Application emits events, core handles logging/encryption
pub trait AppEvent {
    fn event_name(&self) -> &'static str;
}
