//! Reading one file and extracting the declaration at one location.

use std::path::Path;

use pedant_syntax::{Location, SourceUnit, enclosing_unit, syntax_language};

use crate::error::SnippetError;

/// Extract the narrowest declaration containing `at` from the file at `path`.
///
/// Reads `path` as UTF-8, detects the syntax language from the path and the
/// source, then delegates to [`enclosing_unit`]. A relative path resolves from
/// the process working directory and is never canonicalized, so a failure
/// reports the caller's spelling.
///
/// `Ok(None)` covers every absence: a path whose language this crate cannot
/// parse, an unaddressable location, a parser failure, and a point that falls in
/// no recognized declaration. The only error is an unreadable file, including
/// bytes that are not UTF-8.
///
/// # Examples
///
/// ```
/// use std::path::Path;
///
/// use pedant_snippet::{Location, extract_path};
///
/// // A manifest names no syntax language, so extraction is absent, not failed.
/// let at = Location { line: 1, column: None };
/// let unit = extract_path(Path::new("Cargo.toml"), at)?;
///
/// assert_eq!(unit, None);
/// # Ok::<(), pedant_snippet::SnippetError>(())
/// ```
///
/// # Errors
///
/// Returns [`SnippetError::Read`] when the file cannot be read as UTF-8 text.
pub fn extract_path(path: &Path, at: Location) -> Result<Option<SourceUnit>, SnippetError> {
    let source = std::fs::read_to_string(path).map_err(|source| SnippetError::Read {
        path: Box::from(path),
        source,
    })?;
    Ok(syntax_language(path, &source).and_then(|language| enclosing_unit(&source, language, at)))
}
