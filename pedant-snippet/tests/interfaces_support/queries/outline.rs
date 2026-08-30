//! The complete structure forest one admitted source states.

use pedant_snippet::{CodeIntelligenceError, CodeIntelligenceState, StructureDescriptor};
use pedant_syntax::{StructureInventoryLimits, SyntaxLanguage, structure_inventory};

use super::expectations::{FileRows, OUTLINES};
use super::support::{line_at, mixed, rendered, retained_source, the_envelope_round_trips};
use crate::index::sources::MIXED_SOURCES;

/// Every source states its whole row of the closed table, in source order, as
/// one forest whose spans slice the retained text exactly.
///
/// One outline per file, taken once and handed to each of the four claims made
/// about it. Four loops each asking for their own would take thirty-two outlines
/// of eight files and copy every forest out of the index to do it — and the
/// claims are about one answer, not about four answers that happened to agree.
#[test]
fn six_language_outline_is_complete_nested_and_source_exact() {
    let (_repository, state) = mixed();

    // The table is bound to the corpus, not counted against itself. Counting
    // the loop's own iterations restates `OUTLINES.len()` and would let a
    // source added to the mixed repository go silently un-outlined.
    assert_eq!(
        &*OUTLINES
            .iter()
            .map(|file| file.path)
            .collect::<Box<[&str]>>(),
        MIXED_SOURCES,
        "every admitted source of the mixed repository has a row, and nothing else does"
    );

    for file in OUTLINES {
        let outline = outlined(&state, file.path);
        the_forest_is_the_row_the_table_states(file, &outline);
        every_owner_link_stays_in_one_file_and_strictly_contains(file, &outline);
        every_span_slices_the_retained_source_exactly(&state, file, &outline);
        coverage_and_memberships_name_every_reaching_project(&state, file, &outline);
    }

    both_rust_recognizers_state_one_sequence(&state);
    an_unindexed_or_unnormalized_path_refuses(&state);
    the_response_carries_the_state_it_was_answered_from(&state);
}

/// One file's outline, or a panic naming what refused.
///
/// Boxed rather than a `Vec`: the forest is the index's own answer, copied out
/// once so the response can be dropped, and nothing appends to it after.
fn outlined(state: &CodeIntelligenceState, path: &str) -> Box<[StructureDescriptor]> {
    let response = state
        .outline_file(path)
        .unwrap_or_else(|error| panic!("{path} outlines: {error}"));
    assert_eq!(
        response.result().path(),
        path,
        "an outline names the file it was asked for"
    );
    Box::from(response.result().structures())
}

/// One structure as both sides of a comparison name it: what it declares, the
/// name it states, and where its owner sits in the same outline.
///
/// Named because both sides spell it. The expectation side builds this shape
/// from the written-down table and the answer side builds it from the outline,
/// so a column added to one and not the other should stop compiling rather than
/// stop being compared.
type Signature = (String, Option<String>, Option<usize>);

/// One structure as both sides of a comparison name it.
///
/// One projection, because two of them written out separately are two chances
/// for one comparison to stop reading the field the other reads.
fn signature(outline: &[StructureDescriptor], structure: &StructureDescriptor) -> Signature {
    (
        format!("{:?}", structure.kind()),
        structure.name().map(str::to_owned),
        owner_position(outline, structure),
    )
}

/// The forest states every structure the source declares, in source order.
fn the_forest_is_the_row_the_table_states(file: &FileRows, outline: &[StructureDescriptor]) {
    let stated: Box<[Signature]> = outline
        .iter()
        .map(|structure| signature(outline, structure))
        .collect();
    let expected: Box<[Signature]> = file
        .rows
        .iter()
        .map(|row| {
            (
                format!("{:?}", row.kind),
                row.name.map(str::to_owned),
                row.owner,
            )
        })
        .collect();
    assert_eq!(
        stated, expected,
        "{}: the outline states every structure the source declares, in source order",
        file.path
    );
}

/// The position one structure's owner holds in the same outline.
fn owner_position(
    outline: &[StructureDescriptor],
    structure: &StructureDescriptor,
) -> Option<usize> {
    let owner = structure.owner()?;
    outline
        .iter()
        .position(|candidate| candidate.handle() == owner)
        .or_else(|| panic!("an owner link points inside the file that declares it"))
}

/// Every owner sits in the same file, strictly contains what it owns, and the
/// links terminate.
///
/// The lookup is [`owner_position`], which already refuses an owner link that
/// points outside the file that declares it. A second `position` call here was a
/// second panic message for one condition, and the two could disagree about
/// which condition they were reporting.
fn every_owner_link_stays_in_one_file_and_strictly_contains(
    file: &FileRows,
    outline: &[StructureDescriptor],
) {
    for (position, structure) in outline.iter().enumerate() {
        // `owner_position` states `None` only for a structure that names no
        // owner, which is the row this loop has nothing to say about.
        let (Some(owner), Some(owner_at)) = (structure.owner(), owner_position(outline, structure))
        else {
            continue;
        };
        assert!(
            owner_at < position,
            "{}: an owner is declared before what it owns, so the links terminate",
            file.path
        );
        assert!(
            outline[owner_at].span().strictly_contains(structure.span()),
            "{}: structure {position} sits strictly inside its owner",
            file.path
        );
        let nearer = outline.iter().take(position).any(|candidate| {
            candidate.handle() != owner
                && candidate.span().strictly_contains(structure.span())
                && outline[owner_at].span().strictly_contains(candidate.span())
        });
        assert!(
            !nearer,
            "{}: structure {position} names its nearest owner",
            file.path
        );
    }
}

/// Every span slices the text the index retained, and its lines agree with that
/// slice.
fn every_span_slices_the_retained_source_exactly(
    state: &CodeIntelligenceState,
    file: &FileRows,
    outline: &[StructureDescriptor],
) {
    let text = retained_source(state, file.path);
    for (position, structure) in outline.iter().enumerate() {
        let span = structure.span();
        let sliced = text
            .get(span.byte_range())
            .unwrap_or_else(|| panic!("{}: structure {position} slices its source", file.path));
        assert!(
            !sliced.is_empty(),
            "{}: structure {position} covers at least one byte",
            file.path
        );
        if let Some(name) = structure.name() {
            assert!(
                sliced.contains(name),
                "{}: structure {position} contains the name it declares",
                file.path
            );
        }
        assert_eq!(
            span.start_line(),
            line_at(text, span.start_byte() as usize),
            "{}: structure {position} opens on the line its first byte sits on",
            file.path
        );
        let last = span.end_byte().saturating_sub(1).max(span.start_byte());
        assert_eq!(
            span.end_line(),
            line_at(text, last as usize),
            "{}: structure {position} closes on the line its last byte sits on",
            file.path
        );
        assert_eq!(
            structure.line_count(),
            span.end_line() - span.start_line() + 1,
            "{}: structure {position} states the lines its extent covers",
            file.path
        );
    }
}

/// A resolved source names every project that reached it; a syntax-only source
/// names none and says so.
fn coverage_and_memberships_name_every_reaching_project(
    state: &CodeIntelligenceState,
    file: &FileRows,
    outline: &[StructureDescriptor],
) {
    let path = file.path;
    for structure in outline {
        let reaching: Box<[&str]> = structure
            .projects()
            .iter()
            .map(|handle| {
                state
                    .index()
                    .project(*handle)
                    .unwrap_or_else(|error| panic!("{path}: {error}"))
                    .key()
                    .unit()
            })
            .collect();
        assert_eq!(
            &*reaching, file.projects,
            "{path}: every project that reached it"
        );
        assert_eq!(
            structure.coverage(),
            file.coverage,
            "{path}: what kind of evidence stands behind it"
        );
    }
}

/// The loose `syn` route and the resolved site inventory state one sequence.
///
/// Two recognizers answer the Rust row of the contract, in two crates that do
/// not link each other. This is the first root that links both, so it is the
/// only place the comparison can be made: the index's Rust file was inventoried
/// by `pedant-core` because a project reached it, and the same bytes are walked
/// here by `pedant-syntax`.
fn both_rust_recognizers_state_one_sequence(state: &CodeIntelligenceState) {
    let path = "crate-a/src/lib.rs";
    let loose = structure_inventory(
        retained_source(state, path),
        SyntaxLanguage::Rust,
        StructureInventoryLimits::default(),
    )
    .expect("the retained Rust source states a complete inventory")
    .retained();

    let outline = outlined(state, path);
    let resolved: Box<[Signature]> = outline
        .iter()
        .map(|structure| signature(&outline, structure))
        .collect();
    let walked: Box<[Signature]> = loose
        .iter()
        .map(|record| {
            (
                format!("{:?}", record.kind()),
                record.name().map(str::to_owned),
                record.owner().map(|owner| owner as usize),
            )
        })
        .collect();
    // Both sides are held to the written row before they are held to each
    // other. Two recognizers that each stated nothing agree exactly, and this
    // is the one comparison in the file whose expectation is another producer
    // rather than the table.
    let rows = OUTLINES
        .iter()
        .find(|file| file.path == path)
        .expect("the Rust library states a row of the closed table")
        .rows;
    assert_eq!(
        (resolved.len(), walked.len()),
        (rows.len(), rows.len()),
        "each recognizer states the whole Rust row the table writes down"
    );
    assert_eq!(
        resolved, walked,
        "the resolved site inventory and the loose walk state one Rust row"
    );
}

/// A path the index does not hold, and a path that is not a repository
/// spelling, each refuse.
fn an_unindexed_or_unnormalized_path_refuses(state: &CodeIntelligenceState) {
    match state.outline_file("crate-a/src/absent.rs") {
        Err(CodeIntelligenceError::UnknownFile { path }) => {
            assert_eq!(&*path, "crate-a/src/absent.rs")
        }
        other => panic!("an unindexed path is not a source: {}", rendered(&other)),
    }
    for spelling in ["/etc/passwd", "../outside.rs", "web/../web/app.js", ""] {
        match state.outline_file(spelling) {
            Err(CodeIntelligenceError::PathEscape { .. }) => {}
            other => panic!("{spelling} is not a normalized path: {}", rendered(&other)),
        }
    }
}

/// Every response carries both revisions and the health of the state it was
/// answered from.
fn the_response_carries_the_state_it_was_answered_from(state: &CodeIntelligenceState) {
    let response = state
        .outline_file("web/app.ts")
        .expect("the outline answers");
    assert_eq!(response.index_revision(), state.index().revision());
    assert_eq!(response.state_revision(), state.revision());
    assert_eq!(response.health(), state.health());
    assert!(
        response.next_page().is_none(),
        "an outline is one whole forest, not a page of one"
    );

    the_envelope_round_trips(&response);
}
