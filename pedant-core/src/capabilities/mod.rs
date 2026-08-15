mod attribution;
mod detection;
mod paths;
mod strings;
mod validation;

pub use detection::detect_capabilities;
pub use strings::truncate_evidence;

/// The lint pipeline splits detection from projection so semantic reachability
/// can annotate the draft in between; the substrate has no such stage.
#[cfg(feature = "checks")]
pub(crate) use attribution::project_analysis;
#[cfg(feature = "checks")]
pub(crate) use detection::draft_capabilities;

#[cfg(all(feature = "checks", feature = "semantic"))]
pub(crate) use attribution::DraftedFinding;
