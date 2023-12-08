//! Utilities for core sub-protocols.

use std::time::{SystemTime, UNIX_EPOCH};

pub const WAMU_MESSAGE_PREFIX: &str = "\x15Wamu Signed Message:\n";

/// Add predefined prefix to a given message.
pub fn prefix_message_bytes(message: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(WAMU_MESSAGE_PREFIX.len() + message.len());
    result.extend_from_slice(WAMU_MESSAGE_PREFIX.as_bytes());
    result.extend_from_slice(message);
    result
}

/// Returns the unix timestamp in seconds.
pub fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}
