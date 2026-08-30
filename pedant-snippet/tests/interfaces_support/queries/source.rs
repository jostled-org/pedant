//! Reading one structure's exact source, and finding the structure at a point.

use pedant_snippet::{
    CodeIntelligenceError, CodeIntelligenceState, NavigationResponse, StructureDescriptor,
    StructureHandle, StructureSource,
};

use super::support::{mixed, position_of, rendered, retained_source, the_envelope_round_trips};
use crate::index::fixture::Repository;
use crate::index::harness::indexed;
use crate::index::sources::{MIXED_REPOSITORY, PYTHON_TOOL};

/// The Python source of the mixed repository, which two rows below both walk.
const PYTHON_PATH: &str = "scripts/tool.py";

/// Every line the Python source opens a declaration on, and what it declares
/// there.
///
/// One table. The narrowest-structure row and the CRLF row ask about the same
/// six lines, and two hand-written lists are two chances for one of them to
/// stop describing the source.
const PYTHON_DECLARATIONS: [(u32, &str); 6] = [
    (1, "Module"),
    (4, "build"),
    (12, "Job"),
    (13, "run"),
    (17, "start"),
    (21, "make"),
];

/// The bytes the mixed repository wrote at one path.
///
/// Read from the fixture rather than from the index, so a comparison against it
/// is a comparison against the file on disk. Slicing the record the index
/// retained would compare production's own expression to itself: a retained
/// buffer that had drifted from the bytes written would satisfy every row.
fn written(path: &str) -> &'static str {
    MIXED_REPOSITORY
        .iter()
        .find(|(name, _)| *name == path)
        .map(|(_, contents)| *contents)
        .unwrap_or_else(|| panic!("{path} is a source the mixed repository writes"))
}

/// A point selects the narrowest structure containing it, and both source
/// operations return the same structure and the same bytes.
#[test]
fn read_structure_and_structure_at_share_the_exact_narrowest_structure() {
    let (_repository, state) = mixed();

    every_structure_reads_the_bytes_its_span_covers(&state);
    a_point_selects_the_narrowest_structure_containing_it(&state);
    the_two_operations_answer_with_one_structure(&state);
    a_boundary_byte_belongs_to_the_structure_that_covers_it(&state);
    a_byte_column_indexes_bytes_and_not_characters();
    the_same_source_in_crlf_answers_the_same_structures();
    a_point_inside_no_structure_and_a_point_off_the_file_refuse();
    a_handle_from_another_revision_refuses_before_lookup(&state);
}

/// Every indexed structure reads back exactly the bytes its span covers.
fn every_structure_reads_the_bytes_its_span_covers(state: &CodeIntelligenceState) {
    let revision = state.index().revision();
    assert!(
        state.index().structures().len() > 20,
        "the mixed repository states a corpus worth reading"
    );
    for structure in state.index().structures() {
        let handle = StructureHandle::new(revision, structure.id().position());
        let read = state
            .read_structure(handle)
            .unwrap_or_else(|error| panic!("{} reads: {error}", structure.path()));
        assert_eq!(
            read.result().text(),
            written(structure.path())
                .get(structure.span().byte_range())
                .expect("the span slices the bytes the repository wrote"),
            "{}: the read is the source on disk at the span",
            structure.path()
        );
        assert_eq!(read.result().structure().handle(), handle);
        assert_eq!(read.result().structure().kind(), structure.kind());
        assert_eq!(read.result().structure().name(), structure.name());
        assert_eq!(read.result().structure().path(), structure.path());
    }
}

/// A point inside nested structures selects the innermost one.
///
/// Each row asks at the first declared byte of its line, because the leading
/// whitespace of an indented declaration belongs to whatever contains it and a
/// row that asked there would be asserting the owner, not the declaration.
fn a_point_selects_the_narrowest_structure_containing_it(state: &CodeIntelligenceState) {
    let elsewhere: &[(&str, u32, &str)] = &[
        ("crate-a/src/lib.rs", 1, "inner"),
        ("crate-a/src/lib.rs", 2, "Job"),
        ("crate-a/src/lib.rs", 28, "new"),
        ("main.go", 4, "ID"),
        ("web/app.js", 12, "run"),
        ("web/app.ts", 2, "run"),
        ("web/app.ts", 12, "build"),
        ("web/app.ts", 20, "run"),
    ];
    let python = PYTHON_DECLARATIONS.map(|(line, expected)| (PYTHON_PATH, line, expected));

    for (path, line, expected) in python.iter().chain(elsewhere) {
        let column = declared_column(state, path, *line);
        let found = at(state, path, *line, Some(column));
        let structure = found.result().structure();
        assert_eq!(
            declared_name(structure),
            *expected,
            "{path}:{line} selects the narrowest structure containing its declaration"
        );

        // Nothing indexed sits strictly inside the answer and still holds the
        // point, which is what "narrowest" means.
        let offset = offset_of(state, path, *line, column);
        let span = structure.span();
        let narrower = state.index().structures().iter().any(|candidate| {
            candidate.path() == *path
                && span.strictly_contains(candidate.span())
                && candidate.span().byte_range().contains(&offset)
        });
        assert!(
            !narrower,
            "{path}:{line} states no narrower structure over the same point"
        );
    }
}

/// One structure as [`PYTHON_DECLARATIONS`] names it: the name it declares, or
/// its kind where the grammar states none.
///
/// One projection. The narrowest-structure rows and the CRLF rows read the same
/// column of that table, and two spellings of what a row calls a structure are
/// two chances for one of them to compare something else.
fn declared_name(structure: &StructureDescriptor) -> String {
    structure
        .name()
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{:?}", structure.kind()))
}

/// A handle and a point that name one structure answer with one structure.
fn the_two_operations_answer_with_one_structure(state: &CodeIntelligenceState) {
    let column = declared_column(state, PYTHON_PATH, 13);
    let found = at(state, PYTHON_PATH, 13, Some(column));
    let read = state
        .read_structure(found.result().structure().handle())
        .expect("the handle a point returned reads");
    assert_eq!(
        serde_json::to_string(read.result()).expect("the answer serializes"),
        serde_json::to_string(found.result()).expect("the answer serializes"),
        "one structure states one answer, whichever operation named it"
    );

    the_envelope_round_trips(&read);
}

/// The first and last byte of a structure belong to it; the byte after it does
/// not.
fn a_boundary_byte_belongs_to_the_structure_that_covers_it(state: &CodeIntelligenceState) {
    let column = declared_column(state, PYTHON_PATH, 13);
    let inner = at(state, PYTHON_PATH, 13, Some(column));
    let span = inner.result().structure().span();
    let text = retained_source(state, PYTHON_PATH);

    for offset in [span.start_byte() as usize, span.end_byte() as usize - 1] {
        let (line, column) = position_of(text, offset);
        let found = at(state, PYTHON_PATH, line, Some(column));
        assert_eq!(
            found.result().structure().span(),
            span,
            "byte {offset} sits inside the structure whose extent covers it"
        );
    }

    let (line, column) = position_of(text, span.end_byte() as usize);
    let after = at(state, PYTHON_PATH, line, Some(column));
    assert_ne!(
        after.result().structure().span(),
        span,
        "the byte one past a structure is outside it"
    );
}

/// A column is a byte offset within its line, and a line is found by bytes.
///
/// Two disagreements, because a point lookup can lose either one. Within a
/// line, `grüßen` opens at a byte column past its character column; across
/// lines, the third line of the Python source opens at a byte offset past its
/// character offset. A conversion that counted characters at either step would
/// land short of the declaration and answer with whatever contains it.
fn a_byte_column_indexes_bytes_and_not_characters() {
    let inline = "class Grüße { grüßen(): number { return 1; } }\n";
    let across = "class Grüße:\n    def grüßen(self):\n        return \"Grüße 🌍\"\n";
    let repository = Repository::of(&[("multibyte.ts", inline), ("multibyte.py", across)]);
    let state = indexed(&repository);

    let byte_column = inline.find("grüßen").expect("the method name") + 1;
    let character_column = inline.chars().take_while(|held| *held != 'g').count() + 1;
    assert!(
        byte_column > character_column,
        "the fixture line disagrees about bytes and characters"
    );
    assert_named(
        &state,
        ("multibyte.ts", inline),
        1,
        u32::try_from(byte_column).expect("a small column"),
        "grüßen",
    );

    let third = across.find("        return").expect("the third line");
    let characters = across
        .get(..third)
        .expect("the third line opens on a boundary")
        .chars()
        .count();
    assert!(
        third > characters,
        "the fixture's third line opens at byte {third} and character {characters}"
    );
    assert_named(&state, ("multibyte.py", across), 3, 9, "grüßen");
}

/// One point names the declaration it opens, and reads exactly its bytes.
///
/// The expected bytes are sliced out of the source the fixture wrote, which is
/// handed in beside its path. Slicing the buffer the index retained would
/// compare production's own expression to itself and pass over a retained
/// buffer that had drifted from the file.
fn assert_named(
    state: &CodeIntelligenceState,
    source: (&str, &str),
    line: u32,
    column: u32,
    expected: &str,
) {
    let (path, declared) = source;
    let found = at(state, path, line, Some(column));
    assert_eq!(
        found.result().structure().name(),
        Some(expected),
        "{path}:{line}:{column} reaches the declaration its bytes open"
    );
    assert_eq!(
        found.result().text(),
        declared
            .get(found.result().structure().span().byte_range())
            .expect("the span slices multibyte source exactly"),
        "{path}: and the read is exact across multibyte text"
    );
}

/// The same source written with CRLF states the same structures.
///
/// Each side is held to the declaration [`PYTHON_DECLARATIONS`] names, not
/// merely to the other side. Two states that each answered with the enclosing
/// module for all six lines agree with each other exactly, and a comparison
/// that read only that agreement would report the loss as a pass.
fn the_same_source_in_crlf_answers_the_same_structures() {
    let crlf_source = PYTHON_TOOL.replace('\n', "\r\n");
    let lf = Repository::of(&[("tool.py", PYTHON_TOOL)]);
    let crlf = Repository::of(&[("tool.py", &crlf_source)]);
    let lf_state = indexed(&lf);
    let crlf_state = indexed(&crlf);

    for (line, declared) in PYTHON_DECLARATIONS {
        let column = declared_column(&lf_state, "tool.py", line);
        let one = at(&lf_state, "tool.py", line, Some(column));
        let other = at(&crlf_state, "tool.py", line, Some(column));
        assert_eq!(
            declared_name(one.result().structure()),
            declared,
            "line {line} names the declaration the table states"
        );
        assert_eq!(
            declared_name(other.result().structure()),
            declared,
            "line {line} names the same structure whichever line ending the file uses"
        );
        assert_eq!(
            one.result().structure().kind(),
            other.result().structure().kind(),
            "line {line} states the same kind"
        );
        assert_eq!(
            one.result().structure().line_count(),
            other.result().structure().line_count(),
            "line {line} covers the same lines"
        );
        assert_eq!(
            other.result().text(),
            crlf_source
                .get(other.result().structure().span().byte_range())
                .expect("the CRLF span slices exactly"),
            "and its read is the CRLF bytes the fixture wrote"
        );
    }
}

/// A point inside no structure, and a point the file has no position for, each
/// refuse.
fn a_point_inside_no_structure_and_a_point_off_the_file_refuse() {
    let repository = Repository::of(&[("gap.rs", "\npub fn present() {}\n")]);
    let state = indexed(&repository);

    match state.structure_at("gap.rs", 1, None) {
        Err(CodeIntelligenceError::UnenclosedPoint { path, line, column }) => {
            assert_eq!(&*path, "gap.rs");
            assert_eq!((line, column), (1, 1));
        }
        other => panic!("an empty line is inside no structure: {}", rendered(&other)),
    }

    for (line, column) in [(0_u32, None), (9, None), (2, Some(0)), (2, Some(400))] {
        match state.structure_at("gap.rs", line, column) {
            Err(CodeIntelligenceError::UnknownPoint { .. }) => {}
            other => panic!(
                "line {line} column {column:?} is not a position in the file: {}",
                rendered(&other)
            ),
        }
    }

    match state.structure_at("absent.rs", 1, None) {
        Err(CodeIntelligenceError::UnknownFile { .. }) => {}
        other => panic!("an unindexed file has no points: {}", rendered(&other)),
    }
    match state.structure_at("../gap.rs", 1, None) {
        Err(CodeIntelligenceError::PathEscape { .. }) => {}
        other => panic!(
            "an unnormalized path refuses before the point is read: {}",
            rendered(&other)
        ),
    }
}

/// A handle another index issued refuses before the position is read.
fn a_handle_from_another_revision_refuses_before_lookup(state: &CodeIntelligenceState) {
    let other = Repository::of(&[("only.py", "def only():\n    return 1\n")]);
    let other_state = indexed(&other);
    let foreign = StructureHandle::new(other_state.index().revision(), 0);

    match state.read_structure(foreign) {
        Err(CodeIntelligenceError::StaleRevision) => {}
        outcome => panic!(
            "a handle from another revision cannot select a structure: {}",
            rendered(&outcome)
        ),
    }
    assert!(
        state.index().structures().len() > 1,
        "and position zero does exist here, so the refusal is the revision's"
    );
}

/// The structure at one point, or a panic naming what refused.
fn at(
    state: &CodeIntelligenceState,
    path: &str,
    line: u32,
    column: Option<u32>,
) -> NavigationResponse<StructureSource> {
    state
        .structure_at(path, line, column)
        .unwrap_or_else(|error| panic!("{path}:{line} should name a structure: {error}"))
}

/// The one-based byte column of the first declared byte on one line.
fn declared_column(state: &CodeIntelligenceState, path: &str, line: u32) -> u32 {
    let content = retained_source(state, path)
        .split_inclusive('\n')
        .nth(line as usize - 1)
        .unwrap_or_else(|| panic!("{path} states a line {line}"));
    let leading = content.len() - content.trim_start().len();
    u32::try_from(leading + 1).expect("a small column")
}

/// The byte offset one point names in one indexed source.
fn offset_of(state: &CodeIntelligenceState, path: &str, line: u32, column: u32) -> usize {
    let start: usize = retained_source(state, path)
        .split_inclusive('\n')
        .take(line as usize - 1)
        .map(str::len)
        .sum();
    start + column as usize - 1
}
