//! Go's universe block: the names every package sees without importing them.
//!
//! A universe name is defined outside any package, so a snapshot of one
//! repository never holds its definition. Naming the block explicitly is what
//! separates "declared somewhere this corpus does not reach" from "declared
//! nowhere": `len` is the first, a misspelt call is the second, and a report
//! that called both missing would say nothing useful about either.

/// Every predeclared identifier Go's specification states.
///
/// A written-down table rather than a toolchain query: the block is part of the
/// language, and reading it from an installed Go would make one repository
/// state resolve two ways.
const UNIVERSE: &[&str] = &[
    "any",
    "append",
    "bool",
    "byte",
    "cap",
    "clear",
    "close",
    "comparable",
    "complex",
    "complex128",
    "complex64",
    "copy",
    "delete",
    "error",
    "false",
    "float32",
    "float64",
    "imag",
    "int",
    "int16",
    "int32",
    "int64",
    "int8",
    "iota",
    "len",
    "make",
    "max",
    "min",
    "new",
    "nil",
    "panic",
    "print",
    "println",
    "real",
    "recover",
    "rune",
    "string",
    "true",
    "uint",
    "uint16",
    "uint32",
    "uint64",
    "uint8",
    "uintptr",
];

/// Whether one name is declared in the universe block.
pub(super) fn is_predeclared(name: &str) -> bool {
    UNIVERSE.binary_search(&name).is_ok()
}
