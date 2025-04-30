//! # Rust Bus Library
//!
//! This library combines all Rust utilities of dbus-broker. It is linked to
//! most executables of dbus-broker as utility library, relying on link-time
//! garbage collection to drop any unneeded code.

#![no_std]

extern crate alloc;
extern crate core;

/// # Generated Code
///
/// This module exposes all bindgen-generated (or otherwise generated) code,
/// and makes it available to the entire crate.
///
/// Note that any C/Rust interaction is done via bindgen-generated C
/// definitions, to guarantee that the Rust and C definitions never get out
/// of sync.
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub mod generated {
}

#[cfg(test)]
mod test {
    // Simple dummy to show the test-suite in the test results, even if
    // other tests are conditionally disabled.
    #[test]
    fn availability() {
    }
}
