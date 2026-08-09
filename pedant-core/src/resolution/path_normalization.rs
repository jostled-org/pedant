//! Lexical root-relative path normalization shared by resolution adapters.

use std::path::Path;

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
    let relative = path
        .strip_prefix(root)
        .map_err(|_| RelativePathError::OutsideRoot)?;
    let mut text = String::new();
    for component in relative.components() {
        let segment = component
            .as_os_str()
            .to_str()
            .ok_or(RelativePathError::NonUtf8)?;
        push_segment(&mut text, segment);
    }
    Ok(text.into_boxed_str())
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
