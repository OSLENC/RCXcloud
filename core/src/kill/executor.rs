use crate::keystore::KEYSTORE;
use crate::kill::{replay, strategy};

pub fn process_kill(ts: u64) {
    if !replay::check_and_update(ts) {
        return;
    }
    strategy::execute(&KEYSTORE);
}
