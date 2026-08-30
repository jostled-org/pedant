//! What sharing one provider costs, and what it does not excuse.
//!
//! Three claims about the same seam. A file two project slices reach is read
//! once and walked once, which is the whole reason the seam exists. A slice
//! that reached an already-read file still charges it against that slice's own
//! ceilings, because a shared read is not a free source for the corpus that
//! selected it. And a slice that failed leaves every record that did complete
//! behind it, because a repository still holds those files whether or not one
//! project resolved.

use pedant_core::resolution::ResolutionProbe;
use pedant_core::resolution::go::{GoResolutionLimits, GoSnapshotError};
use pedant_core::resolution::rust::{
    ResolutionLimit, ResolutionLimits, RustSourceFault, SourceClosureFailureKind,
};
use pedant_types::{SourcePath, SourceProvider};

use super::go_fixture::{GO_REPOSITORY, GoFixture, PARTIALLY_MALFORMED_GO_REPOSITORY};
use super::rust_fixture::{PARTIALLY_MALFORMED_REPOSITORY, RustFixture, library_of};
use crate::resolution::views::closure_kinds;

/// 3.T4 (Invariant 3): two project slices that share one physical source record
/// one read and one inventory creation between them.
#[test]
fn shared_provider_reads_and_extracts_once_across_project_slices() {
    let fixture = RustFixture::shared(ResolutionLimits::default());

    let probe = ResolutionProbe::install();
    let mut shared = fixture.provider(ResolutionLimits::default());
    let library = fixture
        .project
        .snapshot_resolution_with_provider(&mut shared, fixture.library)
        .unwrap_or_else(|error| panic!("the library slice should snapshot: {error}"));
    let binary = fixture
        .project
        .snapshot_resolution_with_provider(&mut shared, fixture.binary())
        .unwrap_or_else(|error| panic!("the binary slice should snapshot: {error}"));

    assert!(
        library.source("src/shared.rs").is_some() && binary.source("src/shared.rs").is_some(),
        "both slices instantiated the shared source"
    );
    for stream in [probe.source_reads(), probe.parses(), probe.site_visits()] {
        assert_eq!(
            occurrences(&stream, "src/shared.rs"),
            1,
            "the shared source was handled once across both slices: {stream:?}"
        );
        assert_eq!(
            occurrences(&stream, "src/lib.rs"),
            1,
            "the shared library root was handled once across both slices: {stream:?}"
        );
    }
    assert_eq!(
        shared.admitted_sources(),
        3,
        "the repository counter charged each physical record once"
    );

    let control = ResolutionProbe::install();
    for target in [fixture.library, fixture.binary()] {
        fixture
            .project
            .snapshot_resolution(target)
            .unwrap_or_else(|error| panic!("the control snapshot should succeed: {error}"));
    }
    assert_eq!(
        occurrences(&control.source_reads(), "src/shared.rs"),
        2,
        "two private providers read the shared source twice, which is what the seam removes"
    );
}

/// 3.T5 (Invariant 14): a snapshot charges every source it selects against its
/// own ceilings even when the provider had already read it, and a refusal
/// leaves the provider's repository counters untouched.
#[test]
fn provider_hits_recheck_snapshot_limits_without_recharging_repository_state() {
    let fixture = RustFixture::shared(ResolutionLimits::default());
    let mut shared = fixture.provider(ResolutionLimits::default());
    fixture
        .project
        .snapshot_resolution_with_provider(&mut shared, fixture.binary())
        .unwrap_or_else(|error| panic!("the reading snapshot should succeed: {error}"));

    let admitted = shared.admitted_sources();
    let retained = shared.retained_bytes();
    assert_eq!(
        admitted, 3,
        "the provider charged each of the binary's three physical records once"
    );
    assert!(
        retained > 0,
        "the provider retained {retained} bytes, so it holds none of what it read"
    );

    rust_hit_refuses_its_own_file_ceiling(&fixture, &mut shared);
    rust_hit_refuses_its_own_byte_ceiling(&fixture, &mut shared, retained);
    assert_eq!(
        (shared.admitted_sources(), shared.retained_bytes()),
        (admitted, retained),
        "a refused snapshot recharged no repository counter"
    );

    go_hit_refuses_its_own_fact_ceiling();
}

/// 3.T6: a project that failed leaves every completed record available, so a
/// consumer with no resolved slice can still read what was admitted.
#[test]
fn failed_project_snapshot_leaves_completed_facts_for_syntax_fallback() {
    let fixture = RustFixture::of(PARTIALLY_MALFORMED_REPOSITORY, ResolutionLimits::default());
    let mut shared = fixture.provider(ResolutionLimits::default());

    // Installed before the work, not after it. A probe that observed nothing
    // satisfies the "no file was opened" clause below exactly as a live one
    // does, so the refusing snapshot is what proves the stream is running, and
    // the retained reads are then measured against what it recorded.
    let probe = ResolutionProbe::install();
    let refusal = fixture
        .project
        .snapshot_resolution_with_provider(&mut shared, fixture.library)
        .expect_err("the malformed module should refuse the snapshot");
    let opened = probe.source_reads();
    assert!(
        !opened.is_empty(),
        "the refusing snapshot opened the sources it admitted, so the read stream is live"
    );
    assert_eq!(
        &*closure_kinds(&refusal),
        [SourceClosureFailureKind::SourceParse],
        "the refusal names the parse that failed"
    );

    let completed = shared.retained("src/lib.rs").unwrap_or_else(|| {
        panic!("the crate root completed before the malformed module and is retained")
    });
    assert!(
        completed
            .facts()
            .ir()
            .module_declarations
            .iter()
            .any(|site| &*site.name == "good"),
        "the retained record still states everything its source declares"
    );
    assert!(
        shared.retained("src/good.rs").is_some(),
        "a module that completed is retained even though its project did not"
    );
    assert!(
        shared.retained("src/bad.rs").is_none(),
        "a source that stated no inventory became no record"
    );

    let served = shared
        .retained("src/good.rs")
        .expect("the completed module is still held");
    assert!(
        !served.facts().ir().functions.is_empty(),
        "the retained inventory is the one its parse produced"
    );
    assert_eq!(
        probe.source_reads(),
        opened,
        "reading a retained record opened no file the refusing snapshot had not already read"
    );

    go_failure_leaves_its_completed_record();
}

/// A distinct-source ceiling refusal retains no path. Repeating the request
/// must report the ceiling again, because the refused-path memo is bounded by
/// the same ceiling.
#[test]
fn provider_capacity_refusals_are_not_memoized() {
    let fixture = RustFixture::shared(ResolutionLimits::default());
    let mut provider = fixture.provider(ResolutionLimits {
        max_source_files: 1,
        ..ResolutionLimits::default()
    });
    provider
        .source(SourcePath::new("src/lib.rs").expect("the fixture path is normalized"))
        .expect("the first source fits");

    for attempt in 0..2 {
        let refusal = provider
            .source(SourcePath::new("src/shared.rs").expect("the fixture path is normalized"))
            .expect_err("the second distinct source exceeds the ceiling");
        assert!(
            matches!(refusal, RustSourceFault::SourceFiles { ceiling: 1 }),
            "attempt {attempt} reports the capacity fault rather than a memoized refusal: {refusal:?}"
        );
    }
}

/// The Go half: a package walk that refused still leaves the source it did
/// admit as a record a syntax-only consumer can read.
fn go_failure_leaves_its_completed_record() {
    let fixture = GoFixture::of(
        PARTIALLY_MALFORMED_GO_REPOSITORY,
        GoResolutionLimits::default(),
    );
    let mut shared = fixture.provider(GoResolutionLimits::default());

    let refusal = fixture
        .project
        .snapshot_resolution_with_provider(&mut shared)
        .expect_err("the malformed source should refuse the snapshot");
    assert!(
        matches!(refusal, GoSnapshotError::IncompleteSource { .. }),
        "the refusal names the source the grammar could not read: {refusal:?}"
    );

    let completed = shared
        .retained("app/admitted.go")
        .expect("the complete source is retained even though its project did not resolve");
    assert_eq!(
        completed.facts().facts().package_name(),
        Some("app"),
        "the retained record still states everything its source declares"
    );
    assert!(
        shared.retained("app/broken.go").is_none(),
        "a source that stated no inventory became no record"
    );
}

/// A slice whose own distinct-file ceiling is one refuses on the second source,
/// even though the provider already holds all three.
fn rust_hit_refuses_its_own_file_ceiling(
    fixture: &RustFixture,
    shared: &mut pedant_core::resolution::rust::RustSourceProvider,
) {
    let tight = fixture.reloaded(ResolutionLimits {
        max_source_files: 1,
        ..ResolutionLimits::default()
    });
    let target = library_of(&tight);
    let refusal = tight
        .snapshot_resolution_with_provider(shared, target)
        .expect_err("a slice that admits one source must refuse the second");
    assert_eq!(
        &*closure_kinds(&refusal),
        [SourceClosureFailureKind::LimitExceeded(
            ResolutionLimit::SourceFiles
        )],
        "the slice refused on its own file ceiling rather than reading past it"
    );
}

/// A slice whose own total-byte ceiling is below what it selects refuses, even
/// though the provider already read every byte.
fn rust_hit_refuses_its_own_byte_ceiling(
    fixture: &RustFixture,
    shared: &mut pedant_core::resolution::rust::RustSourceProvider,
    retained: u64,
) {
    let tight = fixture.reloaded(ResolutionLimits {
        max_total_source_bytes: 1,
        ..ResolutionLimits::default()
    });
    let target = library_of(&tight);
    let refusal = tight
        .snapshot_resolution_with_provider(shared, target)
        .expect_err("a slice that admits one byte must refuse its first source");
    assert_eq!(
        &*closure_kinds(&refusal),
        [SourceClosureFailureKind::LimitExceeded(
            ResolutionLimit::TotalSourceBytes
        )],
        "the slice refused on its own byte ceiling rather than spending the provider's"
    );
    assert!(
        retained > 1,
        "the provider's own retained total is what the slice did not inherit"
    );
}

/// A Go slice whose own fact ceiling is one refuses a record the provider
/// extracted under a wider one.
fn go_hit_refuses_its_own_fact_ceiling() {
    let fixture = GoFixture::of(GO_REPOSITORY, GoResolutionLimits::default());
    let mut shared = fixture.provider(GoResolutionLimits::default());
    fixture
        .project
        .snapshot_resolution_with_provider(&mut shared)
        .unwrap_or_else(|error| panic!("the reading snapshot should succeed: {error}"));
    let admitted = shared.admitted_sources();

    let tight = fixture.reloaded(GoResolutionLimits {
        max_facts_per_source: 1,
        ..GoResolutionLimits::default()
    });
    let refusal = tight
        .snapshot_resolution_with_provider(&mut shared)
        .expect_err("a slice that admits one fact must refuse a held inventory");
    assert!(
        matches!(refusal, GoSnapshotError::RetainedFactsExceeded { .. }),
        "the Go slice refused the held inventory on its own fact ceiling rather than \
         attributing a refusal to a walk that completed: {refusal:?}"
    );
    assert_eq!(
        shared.admitted_sources(),
        admitted,
        "the refusal recharged no repository counter"
    );
}

/// How many times `path` appears in one observation stream.
fn occurrences(stream: &[Box<str>], path: &str) -> usize {
    stream.iter().filter(|entry| &***entry == path).count()
}
