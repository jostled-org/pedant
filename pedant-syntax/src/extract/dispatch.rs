//! The public extraction entry point and its backend dispatch.

use crate::backend::{Backend, backend};
#[cfg(any(feature = "rust", feature = "_ts"))]
use crate::extract::select::UnitSelector;
use crate::language::SyntaxLanguage;
use crate::location::Location;
use crate::unit::SourceUnit;

/// Extract the smallest recognized declaration containing `at`.
///
/// Lines and columns are one-based. A column is a UTF-8 byte offset within its
/// line; a column-absent location selects by inclusive line containment
/// instead of by exact point. The returned [`SourceUnit::text`] is the
/// byte-exact source slice and its [`SourceUnit::span`] is one-based and
/// inclusive.
///
/// The result is `None` when the location falls in no recognized declaration,
/// when the location is not addressable — a zero line or column, a line past
/// the source, a column past its line, or a column inside a UTF-8 code point —
/// when the parser fails, and when this build disables the backend for
/// `language`. No backend falls back to another parser.
///
/// Extraction reads no file, opens no network connection, and loads no project
/// model. It keeps no state of its own between calls, but the Rust backend's
/// parser does: `proc-macro2` retains every parsed source on a thread-local map
/// that nothing frees. A long-lived process extracting from Rust must call
/// `invalidate_parser_cache`, published behind the `rust` feature, which
/// documents what that costs.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "rust")]
/// # {
/// use pedant_syntax::{Location, SourceUnitKind, SyntaxLanguage, enclosing_unit};
///
/// let source = "struct Job;\n\nimpl Job {\n    fn run(&self) {}\n}\n";
/// let at = Location { line: 4, column: Some(8) };
/// let unit = enclosing_unit(source, SyntaxLanguage::Rust, at).expect("a method");
///
/// assert_eq!(unit.kind, SourceUnitKind::Method);
/// assert_eq!(unit.name.as_deref(), Some("run"));
/// assert_eq!(&*unit.text, "fn run(&self) {}");
/// # }
/// ```
pub fn enclosing_unit(source: &str, language: SyntaxLanguage, at: Location) -> Option<SourceUnit> {
    extract(backend(language)?, source, at)
}

/// Select the narrowest declaration `selected` recognizes at `at`.
///
/// A free function rather than a method on [`Backend`], because that type's own
/// API is its selection and the text its parser sees; what a caller does with
/// the backend it selected belongs to the caller.
///
/// A backend that refuses states no declaration set, which this boundary
/// reports as absence — the same answer it gives for a parser that fails. The
/// refusal is mapped here rather than inside the backend, because a backend
/// that answered "this file declares nothing" would be making a claim about the
/// source it just declined to read.
#[cfg(any(feature = "rust", feature = "_ts"))]
fn extract(selected: Backend, source: &str, at: Location) -> Option<SourceUnit> {
    // The text the parser lexes, which every span it reports is measured
    // against. Extraction returns that slice rather than an offset into the
    // caller's source, so it needs no reading of what the parser discarded.
    let source = selected.parsed_source(source).text();
    let mut selector = UnitSelector::new(source, at)?;
    match selected {
        #[cfg(feature = "rust")]
        Backend::Rust => crate::extract::rust::collect(source, &mut selector),
        #[cfg(feature = "_ts")]
        Backend::TreeSitter(language) => {
            crate::extract::ts::collect(source, language, &mut selector).ok()?
        }
    }
    selector.finish()
}

/// This build links no parser, so no value of this type exists.
#[cfg(not(any(feature = "rust", feature = "_ts")))]
fn extract(selected: Backend, _: &str, _: Location) -> Option<SourceUnit> {
    match selected {}
}
