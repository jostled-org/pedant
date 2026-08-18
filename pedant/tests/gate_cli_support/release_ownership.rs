//! Release-owned dependency versions and the fixed first-party publish order.

/// The graph edge is a versioned normal path dependency whose version follows
/// the graph package, and the graph still releases before the CLI.
pub(crate) fn dependency_edge_is_versioned_and_ordered(
    manifest: &str,
    graph_manifest: &str,
    release_order: &str,
) {
    let graph_version = package_version(graph_manifest);
    let expected_edge =
        format!("pedant-graph = {{ version = \"{graph_version}\", path = \"../pedant-graph\" }}");
    let edges: Vec<&str> = manifest
        .lines()
        .filter(|line| line.trim_start().starts_with("pedant-graph = "))
        .collect();
    assert_eq!(
        edges,
        [expected_edge],
        "exactly one versioned path edge to the graph package"
    );
    let (normal, rest) = manifest
        .split_once("[dev-dependencies]")
        .expect("the manifest states development dependencies");
    assert!(
        normal.contains("pedant-graph = ") && !rest.contains("pedant-graph = "),
        "the graph edge is a normal dependency"
    );

    let graph = release_order
        .find("name = \"pedant-graph\"")
        .expect("the graph package is released");
    let cli = release_order
        .find("name = \"pedant\"\n")
        .expect("the CLI package is released");
    assert!(graph < cli, "the graph publishes before the CLI package");
}

fn package_version(manifest: &str) -> &str {
    manifest
        .lines()
        .skip_while(|line| *line != "[package]")
        .skip(1)
        .take_while(|line| !line.starts_with('['))
        .find_map(|line| {
            line.strip_prefix("version = \"")
                .and_then(|version| version.strip_suffix('"'))
        })
        .expect("the graph package declares its version")
}
