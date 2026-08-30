//! The project authorities a caller may state explicitly.
//!
//! Automatic discovery recognizes `Cargo.toml` and `go.mod` and nothing else. An
//! explicit authority is how a repository that spells its manifest differently
//! is still indexed, so the variants below permit an alternate file name while
//! keeping the language, the root confinement, and the loader fixed. A caller
//! cannot invent a third kind of project this way; it can only point the two
//! that exist at a different file.

use pedant_types::Language;

/// One project authority a caller named rather than one discovery found.
///
/// An explicit authority is always selected, and it suppresses an equal
/// automatic candidate. It is also fatal when it fails: a caller that named a
/// project meant that project, so quietly indexing the repository without it
/// would answer a question nobody asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProjectAuthority {
    /// A Cargo manifest, at a normalized repository path.
    RustManifest {
        /// The normalized repository path of the manifest.
        path: Box<str>,
    },
    /// A Go module manifest, at a normalized repository path.
    GoModule {
        /// The normalized repository path of the manifest.
        path: Box<str>,
    },
}

impl ProjectAuthority {
    /// The language whose loader owns this authority.
    pub fn language(&self) -> Language {
        match self {
            Self::RustManifest { .. } => Language::Rust,
            Self::GoModule { .. } => Language::Go,
        }
    }

    /// The normalized repository path of the manifest.
    pub fn path(&self) -> &str {
        match self {
            Self::RustManifest { path } | Self::GoModule { path } => path,
        }
    }

    /// The order a build selects authorities in: every container before what it
    /// contains.
    ///
    /// The directory leads so a proper-prefix directory sorts first. Language
    /// and path make the order total for authorities in the same directory.
    fn selection_key(&self) -> (&str, Language, &str) {
        let path = self.path();
        (directory_of(path), self.language(), path)
    }
}

/// The directory one normalized authority path sits in, empty at the root.
fn directory_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(cut) => &path[..cut],
        None => "",
    }
}

impl Ord for ProjectAuthority {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.selection_key().cmp(&other.selection_key())
    }
}

impl PartialOrd for ProjectAuthority {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
