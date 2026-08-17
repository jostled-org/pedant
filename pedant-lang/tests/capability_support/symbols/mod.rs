//! Non-Rust symbol-ownership cases, declared by `tests/capability.rs`.
//!
//! Every member here needs a linked tree-sitter grammar, so the whole tree
//! carries one gate at its declaration in the root rather than five copies of
//! the same five-feature predicate. The root reaches this file with `#[path]`
//! for the reason stated there — cargo builds one test executable per
//! `tests/*.rs`, so a support tree must not become a root — and that is the only
//! hop that needs it: the members below are ordinary `mod` items.

mod cases;
mod family_tables;
mod model;
mod module_tables;
mod nesting_tables;
