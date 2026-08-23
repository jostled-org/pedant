//! The public extraction entry point and its backend dispatch.

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
/// [`invalidate_parser_cache`](crate::invalidate_parser_cache), which documents
/// what that costs.
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
    backend(language)?.extract(source, at)
}

/// The parser backend this build links for a syntax language.
///
/// A disabled feature removes its variant, so a configuration that links no
/// parser leaves this type uninhabited and every extraction absent.
#[derive(Clone, Copy)]
enum Backend {
    /// `syn`, behind the `rust` feature.
    #[cfg(feature = "rust")]
    Rust,
    /// A tree-sitter grammar, behind the matching `ts-*` feature.
    #[cfg(feature = "_ts")]
    TreeSitter(SyntaxLanguage),
}

/// The backend `language` selects in this build.
///
/// A tree-sitter language selects the shared tree-sitter backend whenever the
/// build links any grammar; whether that backend links *this* grammar is
/// [`crate::tree_sitter::parse`]'s question, and a missing one is absence there.
/// Rust is the one language whose backend is its own feature.
fn backend(language: SyntaxLanguage) -> Option<Backend> {
    match language {
        #[cfg(feature = "rust")]
        SyntaxLanguage::Rust => Some(Backend::Rust),
        #[cfg(feature = "_ts")]
        SyntaxLanguage::Python
        | SyntaxLanguage::JavaScript
        | SyntaxLanguage::TypeScript
        | SyntaxLanguage::Tsx
        | SyntaxLanguage::Go
        | SyntaxLanguage::Bash => Some(Backend::TreeSitter(language)),
        // Present only while a backend is absent: a language whose feature
        // this build disables selects nothing.
        #[cfg(not(all(feature = "rust", feature = "_ts")))]
        _ => None,
    }
}

impl Backend {
    /// Select the narrowest declaration this backend recognizes at `at`.
    ///
    /// A backend that refuses states no declaration set, which this boundary
    /// reports as absence — the same answer it gives for a parser that fails.
    /// The refusal is mapped here rather than inside the backend, because a
    /// backend that answered "this file declares nothing" would be making a
    /// claim about the source it just declined to read.
    #[cfg(any(feature = "rust", feature = "_ts"))]
    fn extract(self, source: &str, at: Location) -> Option<SourceUnit> {
        let source = self.parsed_source(source);
        let mut selector = UnitSelector::new(source, at)?;
        match self {
            #[cfg(feature = "rust")]
            Self::Rust => crate::extract::rust::collect(source, &mut selector),
            #[cfg(feature = "_ts")]
            Self::TreeSitter(language) => {
                crate::extract::ts::collect(source, language, &mut selector).ok()?
            }
        }
        selector.finish()
    }

    /// The exact text this backend's parser sees.
    ///
    /// A parser that discards a prefix reports every position against what is
    /// left, so the index must cover that same string. `syn` strips a leading
    /// byte-order mark before lexing; indexing the unstripped source instead
    /// leaves every position on line 1 short by the mark's three bytes, which
    /// returns a shifted name and a truncated body rather than an error. A
    /// tree-sitter grammar strips nothing and indexes the source as given.
    ///
    /// `syn` also drops a leading shebang, but it keeps that line's newline, so
    /// line numbers and every later column already agree.
    #[cfg(any(feature = "rust", feature = "_ts"))]
    fn parsed_source(self, source: &str) -> &str {
        match self {
            #[cfg(feature = "rust")]
            Self::Rust => source.strip_prefix('\u{feff}').unwrap_or(source),
            #[cfg(feature = "_ts")]
            Self::TreeSitter(_) => source,
        }
    }

    /// This build links no parser, so no value of this type exists.
    #[cfg(not(any(feature = "rust", feature = "_ts")))]
    fn extract(self, _: &str, _: Location) -> Option<SourceUnit> {
        match self {}
    }
}
