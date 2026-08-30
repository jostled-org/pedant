//! The reference Go source provider: one bounded read and one inventory per
//! normalized path, beneath one canonical repository root.
//!
//! The convenience snapshot entry point builds one of these and throws it away,
//! which is why its behavior is unchanged: a provider that lives for exactly
//! one snapshot reads exactly what that snapshot reaches. A caller that wants a
//! source read once across several snapshots keeps one instead, and then the
//! second snapshot's request is answered from what the first read.
//!
//! The admission belongs to the shared
//! [`RecordCache`](crate::resolution::record_cache::RecordCache) and the facade
//! over it to the shared
//! [`SourceProviderOf`](crate::resolution::SourceProviderOf); what this module
//! states is only the Go half — the ceilings, the confinement rule, the refusal
//! names, and the one call into the Go language owner.

use std::path::{Path, PathBuf};

use pedant_syntax::go::GoFactLimits;

use crate::resolution::provider::SourceProviderOf;
use crate::resolution::read::{ByteCeilings, ReadFault};
use crate::resolution::source_language::SourceLanguage;

use super::error::GoProjectError;
use super::fault::GoSourceFault;
use super::inventory::GoFileInventory;
use super::limits::GoResolutionLimits;
use super::paths;

/// Every Go source one provider has admitted, keyed by normalized path.
pub type GoSourceProvider = SourceProviderOf<GoSourceRules, GoFileInventory>;

impl GoSourceProvider {
    /// A provider that reads Go sources beneath one canonical root.
    ///
    /// The root is canonicalized here rather than taken on trust. Every
    /// confinement test below compares a canonicalized source path against this
    /// root, so a root that is relative, or that reaches its directory through a
    /// symlink, would fail that test for every file and refuse the whole
    /// repository as outside itself.
    pub fn new(root: &Path, limits: GoResolutionLimits) -> Result<Self, GoProjectError> {
        Ok(Self::at_canonical_root(
            paths::canonical_root(root)?,
            GoSourceRules { limits },
        ))
    }

    /// The same provider at a root a loaded project already canonicalized.
    ///
    /// Reachable only from this language module, because only a
    /// [`GoProject`](super::project::GoProject) can state that its root came out
    /// of the same `canonical_root` the constructor above calls.
    pub(super) fn at_project_root(root: PathBuf, limits: GoResolutionLimits) -> Self {
        Self::at_canonical_root(root, GoSourceRules { limits })
    }
}

/// The Go half of one source admission: the ceilings it runs beneath and the
/// vocabulary it refuses in.
///
/// Published because it names the provider above, and inert to a caller: it
/// holds no public field, states no public method, and implements one
/// crate-private trait.
#[derive(Debug)]
pub struct GoSourceRules {
    limits: GoResolutionLimits,
}

impl GoSourceRules {
    /// The two fact ceilings these rules convert their own limits into.
    fn fact_limits(&self) -> GoFactLimits {
        GoFactLimits::new(
            self.limits.max_syntax_depth,
            self.limits.max_facts_per_source,
        )
    }
}

/// The byte ceilings, taken from the limits these rules were built with.
impl ByteCeilings for GoSourceRules {
    fn source_bytes(&self) -> u64 {
        self.limits.source_bytes()
    }

    fn total_bytes(&self) -> u64 {
        self.limits.total_bytes()
    }
}

impl SourceLanguage for GoSourceRules {
    type Inventory = GoFileInventory;
    type Fault = GoSourceFault;

    fn max_source_files(&self) -> u32 {
        self.limits.max_source_files
    }

    fn source_files_fault(&self) -> GoSourceFault {
        GoSourceFault::SourceFiles {
            ceiling: self.limits.max_source_files,
        }
    }

    fn refused_again(&self, path: &str) -> GoSourceFault {
        GoSourceFault::Refused {
            path: Box::from(path),
        }
    }

    /// The canonical location of one request, refused when it leaves the root.
    ///
    /// Absence is not a confinement answer: a path the root does not hold yet
    /// falls through to the read, which reports it with the filesystem's own
    /// reason rather than as an escape.
    fn confine(&self, root: &Path, relative: &str) -> Result<PathBuf, GoSourceFault> {
        let joined = root.join(relative);
        let confined = paths::canonical_in_root(root, &joined)?;
        Ok(confined.unwrap_or(joined))
    }

    fn refusal(&self, fault: ReadFault) -> GoSourceFault {
        GoSourceFault::of_read(fault, self.limits)
    }

    /// The text those bytes state, keeping the decoder's own account of why they
    /// state none.
    ///
    /// `FromUtf8Error` names the offset and the length of the offending
    /// sequence, which is what tells a caller where to look; discarding it left
    /// the refusal saying only that some byte somewhere was wrong.
    fn decode(&self, bytes: Vec<u8>) -> Result<String, GoSourceFault> {
        String::from_utf8(bytes).map_err(|error| GoSourceFault::NonUtf8 {
            reason: error.to_string().into_boxed_str(),
        })
    }

    fn inventory(&self, path: &str, text: &str) -> Result<GoFileInventory, GoSourceFault> {
        GoFileInventory::of_source(path, text, self.fact_limits())
    }
}
