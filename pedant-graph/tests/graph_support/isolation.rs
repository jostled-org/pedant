//! Projection after the repository the facts came from is gone.

use pedant_graph::build_rust_graph;

use super::corpus::MINIMAL_CORPUS;
use super::fixture::Fixture;

/// Construction and serialization succeed after the fixture project is dropped
/// and its owned workspace is removed.
///
/// The release proves the directory is gone before the operations under test
/// run, so a projection that reached a loader, a parser, or the filesystem
/// fails here rather than passing against files that happen to still exist.
pub fn assert_projection_survives_teardown() {
    let fixture = Fixture::build(MINIMAL_CORPUS);
    let resolved = fixture.resolve_library();
    fixture.close();

    let graph = build_rust_graph(&resolved.snapshot, &resolved.resolution)
        .expect("projection needs no repository file");
    let text = serde_json::to_string(&graph).expect("serialization needs no repository file");
    assert!(
        text.starts_with(r#"{"schema_version":1,"tier":"syntactic","#),
        "the graph serialized to an unexpected shape: {text}"
    );
    assert_eq!(graph.nodes().len(), 4);
    assert_eq!(graph.references().len(), 1);
    assert_eq!(graph.edges().len(), 1);
}
