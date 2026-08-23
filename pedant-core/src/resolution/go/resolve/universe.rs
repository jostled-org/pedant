//! Go's universe block: the names every package sees without importing them.
//!
//! A universe name is defined outside any package, so a snapshot of one
//! repository never holds its definition. Naming the block explicitly is what
//! separates "declared somewhere this corpus does not reach" from "declared
//! nowhere": `len` is the first, a misspelt call is the second, and a report
//! that called both missing would say nothing useful about either.

/// Whether one name is declared in the universe block.
///
/// Every predeclared identifier Go's specification states is written down here
/// rather than queried from a toolchain: the block is part of the language, and
/// reading it from an installed Go would make one repository state resolve two
/// ways.
///
/// A match rather than a sorted table searched: a table's order is a second
/// invariant nothing enforces, and one entry dropped in alphabetically by eye
/// makes a real universe name answer `false` — which turns a lookup miss into a
/// missing definition and drops the canonical package prefix from every
/// signature naming that type. The match is order-free, and the compiler builds
/// the lookup rather than the table's author.
pub(super) fn is_predeclared(name: &str) -> bool {
    matches!(
        name,
        "any"
            | "append"
            | "bool"
            | "byte"
            | "cap"
            | "clear"
            | "close"
            | "comparable"
            | "complex"
            | "complex64"
            | "complex128"
            | "copy"
            | "delete"
            | "error"
            | "false"
            | "float32"
            | "float64"
            | "imag"
            | "int"
            | "int8"
            | "int16"
            | "int32"
            | "int64"
            | "iota"
            | "len"
            | "make"
            | "max"
            | "min"
            | "new"
            | "nil"
            | "panic"
            | "print"
            | "println"
            | "real"
            | "recover"
            | "rune"
            | "string"
            | "true"
            | "uint"
            | "uint8"
            | "uint16"
            | "uint32"
            | "uint64"
            | "uintptr"
    )
}
