//! Reading one source into its exact bytes, digest, IR, and module shape.
//!
//! The byte ceilings bound the read itself, through the one bounded reader
//! `resolution::read` owns: at most one byte past the per-source ceiling ever
//! enters memory, and the length both ceilings are compared against is the
//! length that was actually read. This module states which ceilings apply and
//! what each refusal is called here; it does not restate the read.

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use crate::hash::digest_bytes;
use crate::ir::extract as extract_ir;
use crate::ir::extract::{self, ParseCompatibility};
use crate::observe::{self, Observation};
use crate::resolution::read::{self, ReadBounds, ReadFault};
use crate::resolution::rust::edition::CargoEdition;
use crate::resolution::rust::limits::ResolutionLimits;

use super::depth::syntax_depth;
use super::error::{ClosureSite, ResolutionLimit, SourceClosureFailure, SourceClosureFailureKind};
use super::failure::{at_path, limit_failure, read_failure};
use super::source::RustSource;

/// The ceilings one read must respect, and the byte total already consumed.
#[derive(Debug, Clone, Copy)]
pub(super) struct ReadBudget {
    pub(super) limits: ResolutionLimits,
    pub(super) consumed: u64,
}

/// What one source read is about: where it lives and who asked for it.
pub(super) struct ReadRequest<'a> {
    pub(super) canonical: &'a Path,
    pub(super) relative: &'a Arc<str>,
    pub(super) site: &'a ClosureSite,
    pub(super) edition: CargoEdition,
}

/// One read source and the editions its syntax tree supports.
pub(super) struct ReadSource {
    pub(super) source: RustSource,
    pub(super) compatibility: ParseCompatibility,
}

/// Read, hash, and parse one source under `budget`.
pub(super) fn read_source(
    request: &ReadRequest<'_>,
    budget: ReadBudget,
) -> Result<ReadSource, SourceClosureFailure> {
    observe::record(Observation::SourceRead(request.relative));
    let bytes = read::bounded(request.canonical, bounds(budget))
        .map_err(|fault| refusal(fault, request, budget))?;
    let text = decode(bytes, request)?;
    check_syntax_depth(&text, request, budget)?;
    let parsed = parse(&text, request)?;
    Ok(ReadSource {
        source: RustSource {
            digest: digest_bytes(text.as_bytes()),
            ir: extract_ir(request.relative, &parsed.file, None),
            path: Arc::clone(request.relative),
            text: Arc::from(text.as_str()),
        },
        compatibility: parsed.compatibility,
    })
}

/// The byte length of an already-stored source, for the running total.
pub(super) fn byte_length(source: &RustSource) -> u64 {
    read::byte_count(source.text.as_bytes())
}

/// The two byte ceilings this read runs under, and the total already spent.
fn bounds(budget: ReadBudget) -> ReadBounds {
    ReadBounds {
        source_bytes: budget.limits.max_source_file_bytes,
        total_bytes: budget.limits.max_total_source_bytes,
        consumed: budget.consumed,
    }
}

/// The Rust seam's own failure for one refused read.
fn refusal(
    fault: ReadFault,
    request: &ReadRequest<'_>,
    budget: ReadBudget,
) -> SourceClosureFailure {
    let site = (request.site, Some(Box::from(&**request.relative)));
    match fault {
        ReadFault::Unreadable(source) => read_failure(request.site, request.relative, source),
        ReadFault::SourceBytes => limit_failure(
            ResolutionLimit::SourceFileBytes,
            site,
            budget.limits.max_source_file_bytes,
        ),
        ReadFault::TotalBytes => limit_failure(
            ResolutionLimit::TotalSourceBytes,
            site,
            budget.limits.max_total_source_bytes,
        ),
    }
}

fn decode(bytes: Vec<u8>, request: &ReadRequest<'_>) -> Result<String, SourceClosureFailure> {
    String::from_utf8(bytes).map_err(|source| {
        at_path(
            SourceClosureFailureKind::InvalidUtf8,
            (request.site, request.relative),
            format!("{} is not valid UTF-8: {source}", request.relative),
        )
    })
}

/// Hold the text to the nesting ceiling before the recursive parse runs on it.
fn check_syntax_depth(
    text: &str,
    request: &ReadRequest<'_>,
    budget: ReadBudget,
) -> Result<(), SourceClosureFailure> {
    let depth = syntax_depth(text).map_err(|source| invalid_rust(request, &source))?;
    match depth > budget.limits.max_syntax_depth {
        true => Err(limit_failure(
            ResolutionLimit::SyntaxDepth,
            (request.site, Some(Box::from(&**request.relative))),
            budget.limits.max_syntax_depth.into(),
        )),
        false => Ok(()),
    }
}

fn parse(
    text: &str,
    request: &ReadRequest<'_>,
) -> Result<extract::ParsedSource, SourceClosureFailure> {
    extract::parse_source_for_edition(
        request.relative,
        text,
        request.edition.permits_bare_callable_traits(),
    )
    .map_err(|source| invalid_rust(request, &source))
}

fn invalid_rust<E: fmt::Display>(request: &ReadRequest<'_>, source: &E) -> SourceClosureFailure {
    at_path(
        SourceClosureFailureKind::SourceParse,
        (request.site, request.relative),
        format!("{} is not valid Rust: {source}", request.relative),
    )
}
