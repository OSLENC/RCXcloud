pub mod executor;
pub mod verify;

pub use verify::{verify_kill_token,KillDecision};
pub use executor::{execute_kill,is_killed};
