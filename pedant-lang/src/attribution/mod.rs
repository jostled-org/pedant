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

mod envelope;

#[cfg(any(
    feature = "ts-python",
    feature = "ts-javascript",
    feature = "ts-typescript",
    feature = "ts-go",
    feature = "ts-bash"
))]
mod symbols;

pub(crate) use envelope::not_applicable;

/// A backend whose grammar this build omits seals its own text-tier findings
/// through this route. Where every backend links a grammar, `Unavailable` is
/// reached only through [`seal`], so the direct route would be dead code.
#[cfg(not(all(
    feature = "ts-python",
    any(feature = "ts-javascript", feature = "ts-typescript"),
    feature = "ts-go",
    feature = "ts-bash"
)))]
pub(crate) use envelope::unavailable;

#[cfg(any(
    feature = "ts-python",
    feature = "ts-javascript",
    feature = "ts-typescript",
    feature = "ts-go",
    feature = "ts-bash"
))]
pub(crate) use symbols::seal;
