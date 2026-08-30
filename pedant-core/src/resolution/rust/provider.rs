//! The reference Rust source provider: one bounded read and one inventory per
//! normalized path, beneath one canonical repository root.
//!
//! Every convenience snapshot entry point builds one of these and throws it
//! away, which is why their behavior is unchanged: a provider that lives for
//! exactly one snapshot reads exactly what that snapshot reaches. A caller that
//! wants a source read once across several snapshots keeps one instead, and
//! then the second snapshot's request is answered from what the first read.
//!
//! The admission belongs to the shared
//! [`RecordCache`](crate::resolution::record_cache::RecordCache) and the facade
//! over it to the shared
//! [`SourceProviderOf`](crate::resolution::SourceProviderOf); what this module
//! states is only the Rust half — the ceilings, the confinement rule, the
//! refusal names, and the one call into the Rust language owner.

use std::path::{Path, PathBuf};

use crate::resolution::confinement::{ConfinementFault, canonical_present};
use crate::resolution::provider::SourceProviderOf;
use crate::resolution::read::{ByteCeilings, ReadFault};
use crate::resolution::source_language::SourceLanguage;

use super::error::RustProjectError;
use super::fault::RustSourceFault;
use super::inventory::RustFileInventory;
use super::limits::ResolutionLimits;
use super::paths;

/// Every Rust source one provider has admitted, keyed by normalized path.
pub type RustSourceProvider = SourceProviderOf<RustSourceRules, RustFileInventory>;

impl RustSourceProvider {
    /// A provider that reads Rust sources beneath one canonical root.
    ///
    /// The root is canonicalized here rather than taken on trust. Every
    /// confinement test below compares a canonicalized source path against this
    /// root, so a root that is relative, or that reaches its directory through a
    /// symlink, would fail that test for every file and refuse the whole
    /// repository as outside itself.
    pub fn new(root: &Path, limits: ResolutionLimits) -> Result<Self, RustProjectError> {
        Ok(Self::at_canonical_root(
            paths::canonical_root(root)?,
            RustSourceRules { limits },
        ))
    }

    /// The same provider at a root a loaded project already canonicalized.
    ///
    /// Reachable only from this language module, because only a
    /// [`RustProject`](super::project::RustProject) can state that its root came
    /// out of the same `canonical_root` the constructor above calls.
    pub(super) fn at_project_root(root: PathBuf, limits: ResolutionLimits) -> Self {
        Self::at_canonical_root(root, RustSourceRules { limits })
    }
}

/// The Rust half of one source admission: the ceilings it runs beneath and the
/// vocabulary it refuses in.
///
/// Published because it names the provider above, and inert to a caller: it
/// holds no public field, states no public method, and implements one
/// crate-private trait.
#[derive(Debug)]
pub struct RustSourceRules {
    limits: ResolutionLimits,
}

/// The byte ceilings, taken from the limits these rules were built with.
impl ByteCeilings for RustSourceRules {
    fn source_bytes(&self) -> u64 {
        self.limits.source_bytes()
    }

    fn total_bytes(&self) -> u64 {
        self.limits.total_bytes()
    }
}

impl SourceLanguage for RustSourceRules {
    type Inventory = RustFileInventory;
    type Fault = RustSourceFault;

    fn max_source_files(&self) -> u32 {
        self.limits.max_source_files
    }

    fn source_files_fault(&self) -> RustSourceFault {
        RustSourceFault::SourceFiles {
            ceiling: self.limits.max_source_files.into(),
        }
    }

    fn refused_again(&self, path: &str) -> RustSourceFault {
        RustSourceFault::Refused {
            path: Box::from(path),
        }
    }

    /// The canonical location of one request, refused when it leaves the root.
    ///
    /// A path that cannot be resolved at all is unreadable rather than outside:
    /// the filesystem said nothing about where it is, so neither does this. A
    /// path the root does not hold is the same answer, folded back into the
    /// not-found read it is by the one owner of the confinement rule.
    fn confine(&self, root: &Path, relative: &str) -> Result<PathBuf, RustSourceFault> {
        canonical_present(root, &root.join(relative)).map_err(|fault| match fault {
            ConfinementFault::Unreadable(source) => RustSourceFault::Unreadable(source),
            ConfinementFault::OutOfRoot { canonical } => RustSourceFault::OutOfRoot {
                path: Box::from(relative),
                landing: crate::resolution::paths::path_text(&canonical),
            },
        })
    }

    fn refusal(&self, fault: ReadFault) -> RustSourceFault {
        RustSourceFault::of_read(fault, self.limits)
    }

    fn decode(&self, bytes: Vec<u8>) -> Result<String, RustSourceFault> {
        String::from_utf8(bytes).map_err(|error| RustSourceFault::InvalidUtf8 {
            reason: error.to_string().into_boxed_str(),
        })
    }

    fn inventory(&self, path: &str, text: &str) -> Result<RustFileInventory, RustSourceFault> {
        RustFileInventory::of_source(path, text, self.limits.max_syntax_depth)
    }
}
