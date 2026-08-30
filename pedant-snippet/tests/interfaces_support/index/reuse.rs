//! Source work retained across a refused project admission.

use pedant_snippet::SourceStep;

use super::fixture::Repository;
use super::harness::{indexed, issue_rows, paths};

/// A project parser refusal is the cached parse outcome for that physical
/// source. Loose admission must not invoke another parser to replace it.
#[test]
fn code_intelligence_loose_fallback_reuses_the_project_read() {
    let repository = Repository::of(&[
        ("go.mod", "module example.com/refused\n\ngo 1.22\n"),
        ("main.go", "func Kept() {}\n"),
    ]);
    let state = indexed(&repository);

    assert_eq!(
        &*paths(&state),
        [] as [&str; 0],
        "a refused parse is not replaced by a second parser"
    );
    assert_eq!(
        state.index().source_work().reads(),
        1,
        "one physical source is opened, hashed, and decoded once"
    );
    assert_eq!(
        state.index().source_work().parses(),
        1,
        "one physical source is handed to one parser once"
    );
    assert_eq!(
        &*issue_rows(&state),
        [
            "file:main.go|inventory|inventory_incomplete|false",
            "project:go.mod|snapshot|snapshot_refused|false",
        ],
        "both routes report the one cached refusal"
    );
    assert_eq!(
        state
            .index()
            .source_work()
            .trace()
            .iter()
            .filter(|event| {
                event.source() == "main.go" && event.step() == SourceStep::StoreRead
            })
            .count(),
        1,
        "the trace records the one physical read"
    );
}
