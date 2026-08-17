//! Who in this crate may build a parser, and what a bound session may do.
//!
//! Declared by `tests/enclosing_unit.rs` with `#[path]`, for the reason stated
//! there — cargo builds one test executable per `tests/*.rs`, so a support tree
//! must not become a root — and that is the only hop that needs it: the members
//! below are ordinary `mod` items.
//!
//! The whole tree needs `rust` for the parser it scans with and `_ts` for the
//! session it scans about, so it carries one gate at its declaration in the root
//! rather than a copy per member.

mod claims;
mod closure;
mod modules;
mod scan;
