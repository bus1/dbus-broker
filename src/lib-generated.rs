//! # Generated Rust Code
//!
//! This Rust crate bundles all generated Rust artifacts (mainly from
//! `bindgen`) into a single Rust crate. It is then linked into the other
//! Rust crates that need access to it.
//!
//! The main reason for separating generated code is to simplify build
//! definitions: Rust relies on a structured source tree, which is hard to
//! replicate when generating sources in a read-only source directory. Instead
//! of copying everything, we separate generated sources into private crates
//! and pull them in from all its users.

#![no_std]

extern crate alloc;
extern crate core;

#[allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
)]
mod generated {
    pub mod session_main;
    pub mod util_acct;
}

// The build system puts generated sources in a `./generated/*` sub-directory.
// Lets strip this from any paths, given that the crate is already specific to
// generated sources.
pub use generated::*;
