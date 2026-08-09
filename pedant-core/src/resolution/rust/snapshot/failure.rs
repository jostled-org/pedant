//! Constructors that bind every closure failure to the same evidence shape.

use super::error::{ClosureSite, ResolutionLimit, SourceClosureFailure, SourceClosureFailureKind};

/// Bind a failure kind to its declaring site, attempted path, and message.
pub(super) fn failure(
    kind: SourceClosureFailureKind,
    evidence: (&ClosureSite, Option<Box<str>>),
    message: String,
) -> SourceClosureFailure {
    let (site, attempted) = evidence;
    SourceClosureFailure::new(kind, (site.clone(), attempted), message.into_boxed_str())
}

/// A failure whose attempted path stayed inside the repository root.
pub(super) fn at_path(
    kind: SourceClosureFailureKind,
    context: (&ClosureSite, &str),
    message: String,
) -> SourceClosureFailure {
    let (site, relative) = context;
    failure(kind, (site, Some(Box::from(relative))), message)
}

/// A read or metadata failure reported against its declaring site.
pub(super) fn read_failure(
    site: &ClosureSite,
    relative: &str,
    source: std::io::Error,
) -> SourceClosureFailure {
    at_path(
        site.read_kind(),
        (site, relative),
        format!("{relative} could not be read: {source}"),
    )
}

/// A crossed ceiling, naming the `ResolutionLimits` field that owns it.
pub(super) fn limit_failure(
    limit: ResolutionLimit,
    evidence: (&ClosureSite, Option<Box<str>>),
    ceiling: u64,
) -> SourceClosureFailure {
    let message = format!("the configured {limit} ceiling of {ceiling} is exceeded");
    failure(
        SourceClosureFailureKind::LimitExceeded(limit),
        evidence,
        message,
    )
}
