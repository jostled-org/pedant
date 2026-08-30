//! Root confinement, and the one normalized spelling every stored path takes.
//!
//! Every path this crate stores is repository-relative, `/`-separated, and made
//! of real segments. That is not a formatting preference: it is what makes a
//! path usable as the physical-file key, because two spellings of one file
//! would be two records of it. Normalization refuses rather than repairs, for
//! the reason [`SourcePath`](pedant_types::SourcePath) states — a repaired path
//! is a path the caller and the index disagree about.
//!
//! Confinement is checked against the canonical root, so a symlink is followed
//! only far enough to learn where it points and never far enough to read it.

use std::path::{Component, Path, PathBuf};

use super::error::CodeIntelligenceError;

/// The canonical directory an index is rooted at.
///
/// Holding one is the claim that the root existed, was a directory, and
/// canonicalized: every later confinement check compares against this value
/// rather than against the spelling a caller supplied.
#[derive(Clone, Debug)]
pub(crate) struct CanonicalRoot {
    path: PathBuf,
}

impl CanonicalRoot {
    /// Canonicalize one requested root, or state why it is not one.
    pub(crate) fn open(root: &Path) -> Result<Self, CodeIntelligenceError> {
        let path = root
            .canonicalize()
            .map_err(|source| CodeIntelligenceError::InvalidRoot {
                path: render(root),
                reason: source.to_string().into_boxed_str(),
            })?;
        match path.is_dir() {
            true => Ok(Self { path }),
            false => Err(CodeIntelligenceError::InvalidRoot {
                path: render(root),
                reason: Box::from("the root is not a directory"),
            }),
        }
    }

    /// The canonical root itself.
    pub(crate) fn as_path(&self) -> &Path {
        &self.path
    }

    /// Where one normalized repository path sits on this filesystem.
    ///
    /// The whole resolved location is compared with the root, so a symlink
    /// pointing out of the repository is refused here — before it is opened —
    /// rather than after a read has already followed it.
    ///
    /// A refusal carries where the request landed as well as how it was
    /// spelled. This is the only seam that resolves the two together, and a
    /// language owner asking through the provider seam names both.
    pub(crate) fn resolve(&self, relative: &str) -> Result<PathBuf, CodeIntelligenceError> {
        let normalized = normalize(relative)?;
        let joined = self.path.join(normalized);
        let canonical =
            joined
                .canonicalize()
                .map_err(|source| CodeIntelligenceError::SourceRead {
                    path: Box::from(normalized),
                    reason: source.to_string().into_boxed_str(),
                })?;
        match canonical.starts_with(&self.path) {
            true => Ok(canonical),
            false => Err(CodeIntelligenceError::SymlinkEscape {
                landing: render(&canonical),
                path: Box::from(normalized),
            }),
        }
    }

    /// The normalized repository spelling of one path beneath this root.
    ///
    /// Absent when the path is not beneath the root at all, and refused when
    /// the segments beneath it have no UTF-8 spelling: an index that stored a
    /// lossy rendering would key a record under a name no request can produce.
    ///
    /// A refusal names the suffix rather than the whole path. The lossy
    /// rendering reaches an issue, an issue reaches the state claim, and a
    /// claim that carried the root's absolute spelling would give one
    /// repository two identities on two machines.
    ///
    /// A backslash in a native segment is refused before the normalized key is
    /// minted. Otherwise a Unix file named `a\b.rs` collides with `a/b.rs`.
    pub(crate) fn relative(&self, path: &Path) -> Result<Option<Box<str>>, CodeIntelligenceError> {
        let Ok(suffix) = path.strip_prefix(&self.path) else {
            return Ok(None);
        };
        // The separators the walk hands back are one byte each and so is the
        // one written between segments, so the suffix's own length is the exact
        // reservation. Grown from empty this doubled its way to the answer and
        // the boxing then reallocated and copied it again, once per walked
        // entry.
        let mut spelled = String::with_capacity(suffix.as_os_str().len());
        for component in suffix.components() {
            let Component::Normal(segment) = component else {
                return Err(CodeIntelligenceError::PathEscape {
                    path: render(suffix),
                });
            };
            let Some(text) = segment.to_str() else {
                return Err(CodeIntelligenceError::PathEncoding {
                    path: render(suffix),
                });
            };
            if text.contains('\\') {
                return Err(CodeIntelligenceError::PathEscape {
                    path: render(suffix),
                });
            }
            if !spelled.is_empty() {
                spelled.push('/');
            }
            spelled.push_str(text);
        }
        Ok(Some(spelled.into_boxed_str()))
    }
}

/// One repository-relative path, refused unless it is already normalized.
///
/// Absolute paths, `..` segments, `.` segments, empty segments, and backslash
/// separators are each a different spelling of "this is not the key the index
/// stores", and every one of them is refused before a filesystem call.
///
/// Two of those are the segment scan. The empty path splits into one empty
/// segment and a leading `/` splits into an empty segment before the rest, so
/// the scan already refuses both — testing them again stated the same rule
/// twice and left one copy free to disagree.
///
/// The accepted path comes back borrowed. Normalization refuses rather than
/// repairs, so an accepted spelling is byte-for-byte the one that arrived, and
/// owning it copied every path of every `outline_file` and `structure_at`
/// query to hand back what the caller already held. Only the refusal needs a
/// copy, and it takes one where it is built.
pub(crate) fn normalize(relative: &str) -> Result<&str, CodeIntelligenceError> {
    let refused = relative.contains('\\')
        || relative
            .split('/')
            .any(|segment| matches!(segment, "" | "." | ".."));
    match refused {
        true => Err(CodeIntelligenceError::PathEscape {
            path: Box::from(relative),
        }),
        false => Ok(relative),
    }
}

/// One path as a diagnostic names it.
///
/// Lossy, and only ever used inside a message: a path with no UTF-8 spelling is
/// refused as a key, and a refusal that could not name it would leave the
/// caller nothing to look for.
///
/// Boxed straight out of the borrowed rendering. A lossless path lends its own
/// bytes and is copied once; the owning step in between copied it a second time
/// and then reallocated to shed the capacity that copy had reserved.
pub(crate) fn render(path: &Path) -> Box<str> {
    Box::from(path.to_string_lossy())
}
