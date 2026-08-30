//! Lexical root-relative path normalization shared by resolution adapters.

use std::path::Path;
use std::sync::Arc;

/// Why a path has no UTF-8 representation relative to the requested root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RelativePathError {
    /// The path does not begin with the root's lexical components.
    OutsideRoot,
    /// A relative component has no UTF-8 representation.
    NonUtf8,
}

/// Render `path` beneath `root` as lexical, `/`-separated UTF-8 text.
pub(crate) fn relative_text(root: &Path, path: &Path) -> Result<Box<str>, RelativePathError> {
    let mut text = String::new();
    write_relative(&mut text, root, path)?;
    Ok(text.into_boxed_str())
}

/// The same rendering, shared rather than owned.
///
/// Used when several records retain the same normalized path.
pub(crate) fn relative_shared(root: &Path, path: &Path) -> Result<Arc<str>, RelativePathError> {
    let mut text = String::new();
    write_relative(&mut text, root, path)?;
    Ok(Arc::from(text.as_str()))
}

/// The same rendering into a buffer the caller keeps.
///
/// The buffer is cleared before rendering, including on a refused path.
pub(crate) fn write_relative(
    text: &mut String,
    root: &Path,
    path: &Path,
) -> Result<(), RelativePathError> {
    text.clear();
    let relative = path
        .strip_prefix(root)
        .map_err(|_| RelativePathError::OutsideRoot)?;
    for component in relative.components() {
        let segment = component
            .as_os_str()
            .to_str()
            .ok_or(RelativePathError::NonUtf8)?;
        push_segment(text, segment);
    }
    Ok(())
}

fn push_segment(text: &mut String, segment: &str) {
    match text.is_empty() {
        true => text.push_str(segment),
        false => {
            text.push('/');
            text.push_str(segment);
        }
    }
}
