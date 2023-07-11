//! # Rust Bus Crate
//!
//! This library combines all Rust utilities of dbus-broker. It is linked to
//! most executables of dbus-broker as utility library, relying on link-time
//! garbage collection to drop any unneeded code.

#![allow(
    clippy::redundant_field_names,
)]

extern crate alloc;
extern crate core;

pub mod session;
pub mod util;

#[cfg(test)]
mod test {
    // Simple dummy to show the test-suite in the test results, even if
    // other tests are conditionally disabled.
    #[test]
    fn availability() {
    }
}
