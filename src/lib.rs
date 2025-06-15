//! D-Bus Broker Support Library
//!
//! This rust library provides all the implementation details of the entire
//! dbus-broker code-base. It is compiled into a single archive and then linked
//! into each target, if needed. The linker is expected to strip all unused
//! parts of the library.

pub mod session;
