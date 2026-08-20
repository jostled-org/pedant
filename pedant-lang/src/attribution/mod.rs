//! Grouping non-Rust capability findings under the callables that contain them.
//!
//! One projection serves every structured backend. A backend hands over the
//! parse session it already bound and the findings it already produced; this
//! module asks that same session which declaration holds each finding and seals
//! the result. It parses nothing, reads no file, loads no project, and runs no
//! process.
//!
//! The status is the honest part. A build that links no grammar, a parser that
//! produced no tree, and a tree the parser recovered from all report
//! [`SymbolAttributionStatus::Unavailable`](pedant_types::SymbolAttributionStatus::Unavailable)
//! beside their unchanged flat findings, rather than a successful analysis with
//! an empty symbol list.

//! Both owners are named where they are called, rather than re-exported here.
//! A re-export would need the same five-feature disjunction the module below
//! already carries — once for `seal`, and again for the envelope route a
//! grammar-less backend takes — so the predicate would be written three times
//! and would have to be kept identical. One `cfg` on one module is the whole
//! condition, and a caller reads which owner answers it from the path it types.

pub(crate) mod envelope;

#[cfg(any(
    feature = "ts-python",
    feature = "ts-javascript",
    feature = "ts-typescript",
    feature = "ts-go",
    feature = "ts-bash"
))]
pub(crate) mod anchors;

#[cfg(any(
    feature = "ts-python",
    feature = "ts-javascript",
    feature = "ts-typescript",
    feature = "ts-go",
    feature = "ts-bash"
))]
pub(crate) mod symbols;
