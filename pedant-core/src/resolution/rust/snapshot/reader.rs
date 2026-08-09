//! Reading one source into its exact bytes, digest, IR, and module shape.
//!
//! The per-source byte ceiling bounds the read itself: at most one byte past
//! the ceiling ever enters memory, and the length the ceiling is compared
//! against is the length that was actually read. A separate stat could not
//! state that, because a file may grow between the stat and the read.

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use crate::hash::digest_bytes;
use crate::ir::extract as extract_ir;
use crate::ir::extract::{self, ParseCompatibility};
use crate::observe::{self, Observation};
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
    let bytes = read_bounded(request, budget)?;
    check_total(request, budget, byte_count(&bytes))?;
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
    u64::try_from(source.text.len()).unwrap_or(u64::MAX)
}

/// Read at most one byte past the per-source ceiling, then hold the bytes that
/// actually arrived to it.
fn read_bounded(
    request: &ReadRequest<'_>,
    budget: ReadBudget,
) -> Result<Vec<u8>, SourceClosureFailure> {
    let ceiling = budget.limits.max_source_file_bytes;
    let mut bytes = Vec::new();
    File::open(request.canonical)
        .and_then(|file| file.take(ceiling.saturating_add(1)).read_to_end(&mut bytes))
        .map_err(|source| read_failure(request.site, request.relative, source))?;
    match byte_count(&bytes) > ceiling {
        true => Err(limit_failure(
            ResolutionLimit::SourceFileBytes,
            (request.site, Some(Box::from(&**request.relative))),
            ceiling,
        )),
        false => Ok(bytes),
    }
}

/// The read length, as the ceilings count it.
fn byte_count(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

fn check_total(
    request: &ReadRequest<'_>,
    budget: ReadBudget,
    length: u64,
) -> Result<(), SourceClosureFailure> {
    match budget.consumed.saturating_add(length) > budget.limits.max_total_source_bytes {
        true => Err(limit_failure(
            ResolutionLimit::TotalSourceBytes,
            (request.site, Some(Box::from(&**request.relative))),
            budget.limits.max_total_source_bytes,
        )),
        false => Ok(()),
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
