//! The Go project boundary: exactly which files a load reads, and which
//! authorities its source may never consult.
//!
//! The observed half names every `go.mod` the production loader opened, so a
//! manifest read outside the admitted set is a failure rather than an unasked
//! question. The structural half reads the same closure's text, because a
//! process, a network client, or a `GOPATH` lookup added later would not change
//! any manifest count.

use std::path::Path;

use pedant_core::resolution::ResolutionProbe;
use pedant_core::resolution::go::{GoProject, GoResolutionLimits};
use pedant_types::Capability;

use crate::declaration_scan::{capability_findings, crate_path, read_source};
use crate::resolution::fixture::{build_repository, repository_root};
use crate::resolution::go::owners::source_closure;
use crate::resolution::go::project_fixtures::DIRECTIVE_AUTHORITY;

/// Every manifest a [`DIRECTIVE_AUTHORITY`] load may open, in read order.
///
/// The three unread manifests in that tree are the point: `local/outranked`
/// lost precedence, `local/unused` is required by nobody, and
/// `local/exact/child-ignored` is named only by a child manifest.
const READ_MANIFESTS: &[&str] = &["go.mod", "local/exact/go.mod", "local/wide/go.mod"];

/// Authorities the Go loader must never consult. Each is the text that would
/// prove the consultation, with the complete set of owners allowed to name it.
const FORBIDDEN_AUTHORITIES: &[(&str, &[&str])] = &[
    ("go.work", &[]),
    ("GOPATH", &[]),
    ("GOROOT", &[]),
    ("GOMODCACHE", &[]),
    ("GOFLAGS", &[]),
    ("GOOS", &[]),
    ("GOARCH", &[]),
    ("CGO_ENABLED", &[]),
    ("vendor", &[]),
    ("pkg/mod", &[]),
    ("std::env", &[]),
    ("env::var", &[]),
    ("std::process", &[]),
    ("Command", &[]),
    ("std::net", &[]),
    ("consts::OS", &[]),
    ("consts::ARCH", &[]),
];

/// The capability every closure owner may state: a load reads manifests.
const ADMITTED_CAPABILITIES: &[Capability] = &[Capability::FileRead];

/// The capability one named owner may state, and no other owner may.
///
/// A project identity is scoped by a SHA-256 digest over manifest bytes, so
/// `hash.rs` reaches `sha2` and states `Crypto`. Naming the owner keeps that
/// from becoming a closure-wide allowance: a Go module that hashed anything
/// would have to justify itself here first.
const OWNED_CAPABILITIES: &[(&str, Capability)] = &[("hash.rs", Capability::Crypto)];

/// 3.T5 (Invariant 4): a Go project load reads only the manifests it admits,
/// inside the root, and its source consults no host, process, or network
/// authority.
#[test]
fn go_project_and_snapshot_are_in_root_and_parse_only() {
    assert_observed_manifest_reads();
    assert_closure_names_no_forbidden_authority();
    assert_closure_states_only_bounded_file_reads();
}

/// The production loader opens one project index and exactly the admitted
/// manifests, each once.
fn assert_observed_manifest_reads() {
    let tree = build_repository(DIRECTIVE_AUTHORITY, false);
    let probe = ResolutionProbe::install();
    let project = GoProject::load(&repository_root(&tree), GoResolutionLimits::default())
        .expect("the fixture should load");

    let observed = probe.manifest_reads();
    let reads: Box<[&str]> = observed.iter().map(|path| &**path).collect();
    assert_eq!(
        &*reads, READ_MANIFESTS,
        "a load reads exactly the manifests it admits, once each"
    );
    assert_eq!(
        probe.project_loads(),
        1,
        "one call to load builds one project index"
    );
    assert_eq!(
        probe.source_reads().len(),
        0,
        "loading a project opens no Go source"
    );

    let root = project.root().to_path_buf();
    drop(project);
    drop(probe);
    drop(tree);
    assert!(
        !root.exists(),
        "the fixture is released with the temporary directory"
    );
}

/// No source in the closure names an authority the boundary excludes.
fn assert_closure_names_no_forbidden_authority() {
    let closure = source_closure();
    let mut offenders: Vec<Box<str>> = Vec::new();
    for path in &closure {
        let text = read_source(path);
        let name = file_label(path);
        for (marker, allowed) in FORBIDDEN_AUTHORITIES {
            if text.contains(marker) && !allowed.contains(&&*name) {
                offenders.push(format!("{name} names {marker}").into_boxed_str());
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "the Go project closure consults excluded authorities: {offenders:?}"
    );
}

/// The closure's declared capabilities are bounded file reads, plus the one
/// digest its named owner states.
fn assert_closure_states_only_bounded_file_reads() {
    let closure = source_closure();
    let mut offenders: Vec<Box<str>> = Vec::new();
    let mut reads = 0_usize;
    let mut owned: Vec<(&str, Capability)> = Vec::new();
    for path in &closure {
        let label = file_label(path);
        for (capability, evidence) in capability_findings(path).iter() {
            match admission(&label, *capability) {
                Admission::Closure => reads += 1,
                Admission::Owner(owner) => owned.push((owner, *capability)),
                Admission::Refused => offenders
                    .push(format!("{label}: {capability} through {evidence}").into_boxed_str()),
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "the Go project closure states capabilities outside its boundary: {offenders:?}"
    );
    assert!(
        reads > 0,
        "the closure reads manifests, so the capability scan must not be vacuous"
    );
    owned.sort_unstable();
    owned.dedup();
    assert_eq!(
        &*owned, OWNED_CAPABILITIES,
        "every owner exception must still be earned by the source it names"
    );
}

/// How one owner's capability is admitted, if it is admitted at all.
enum Admission {
    /// Every closure owner may state it.
    Closure,
    /// Only the named owner may state it.
    Owner(&'static str),
    /// The boundary excludes it.
    Refused,
}

fn admission(label: &str, capability: Capability) -> Admission {
    if ADMITTED_CAPABILITIES.contains(&capability) {
        return Admission::Closure;
    }
    match OWNED_CAPABILITIES
        .iter()
        .find(|(owner, owned)| *owner == label && *owned == capability)
    {
        Some((owner, _)) => Admission::Owner(owner),
        None => Admission::Refused,
    }
}

/// One closure owner's name, relative to `src`.
///
/// Relative rather than bare: the closure holds three `mod.rs` files, and an
/// offender report that named only the file would not say which module it came
/// from.
fn file_label(path: &Path) -> Box<str> {
    path.strip_prefix(crate_path("src"))
        .unwrap_or_else(|_| panic!("{} is a closure owner beneath src", path.display()))
        .to_string_lossy()
        .into_owned()
        .into_boxed_str()
}
