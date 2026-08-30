//! Every closed graph vocabulary's published list, and the token it claims.
//!
//! Four request enums state an `ALL` array beside their variants, and the MCP
//! registry builds the client-facing schema out of those arrays. The arrays are
//! fixed-length and hand-written, so a sixth variant added beside a bumped
//! length literal compiles: the derived `Deserialize` accepts its token and the
//! schema never advertises it. Nothing in the product binds an array to its
//! variant set, so this root does.
//!
//! The same guard `pedant-types` keeps over its own vocabularies, in the same
//! shape. Two roots rather than one shared helper: an integration test links its
//! crate and the dev-dependencies, never another crate's test tree.

use pedant_snippet::{AnalysisMode, EdgeCertainty, EdgeKind, RelationDirection};

/// Declare one vocabulary's variant list and the assertion over it from a
/// single written-down table.
///
/// A hand-written array of listed variants keeps compiling when the model gains
/// one: only an exhaustive match breaks, and the array silently stays a row
/// short. Generating both from one list closes that. The match fails to compile
/// until the new variant is listed, listing it grows the array, and the array is
/// then what the model's own published list is measured against.
macro_rules! stated_vocabulary {
    ($enum:ident, $listed:ident, $asserted:ident, $($variant:ident => $token:literal),+ $(,)?) => {
        /// Every variant this root states for the vocabulary, in the order the
        /// model declares them.
        const $listed: [$enum; [$(stringify!($variant)),+].len()] = [$($enum::$variant),+];

        /// The published list is exactly the variants above, in the same order,
        /// each claiming the token serde spells it with.
        fn $asserted() {
            assert_eq!(
                $enum::ALL.len(),
                $listed.len(),
                "{}::ALL publishes one entry per declared variant",
                stringify!($enum)
            );
            for (position, value) in $listed.into_iter().enumerate() {
                assert_eq!(
                    $enum::ALL[position],
                    value,
                    "{}::ALL states {value:?} at position {position}",
                    stringify!($enum)
                );
                // The token this root states, independent of the model's own
                // `token` method. Exhaustive, so a new variant fails to compile
                // here until it is listed in the table above.
                let token = match value {
                    $($enum::$variant => $token),+
                };
                assert_eq!(
                    value.token(),
                    token,
                    "{}::token claims the spelling this root states for {value:?}",
                    stringify!($enum)
                );
                // The spelling is asserted rather than inferred from a round
                // trip alone: a variant renamed in Rust is a source change, and
                // a variant renamed on the wire is a break for every client
                // that reads the schema this vocabulary builds.
                let encoded = serde_json::to_string(&value).expect("a closed enum serializes");
                assert_eq!(
                    encoded,
                    format!("\"{token}\""),
                    "{value:?} must spell itself {token} on the wire"
                );
                let restored: $enum =
                    serde_json::from_str(&encoded).expect("its own token deserializes");
                assert_eq!(restored, value, "{value:?} round trips through {token}");
            }
        }
    };
}

stated_vocabulary!(
    EdgeKind,
    STATED_EDGE_KINDS,
    assert_edge_kinds_published,
    Call => "call",
    Import => "import",
    Implementation => "implementation",
    Reference => "reference",
    DependsOn => "depends_on",
);

stated_vocabulary!(
    EdgeCertainty,
    STATED_EDGE_CERTAINTIES,
    assert_edge_certainties_published,
    Resolved => "resolved",
    Possible => "possible",
);

stated_vocabulary!(
    RelationDirection,
    STATED_RELATION_DIRECTIONS,
    assert_relation_directions_published,
    Outgoing => "outgoing",
    Incoming => "incoming",
    Both => "both",
);

stated_vocabulary!(
    AnalysisMode,
    STATED_ANALYSIS_MODES,
    assert_analysis_modes_published,
    DegreeCentrality => "degree_centrality",
    BetweennessCentrality => "betweenness_centrality",
    Components => "components",
    Condensation => "condensation",
    ModuleDivergence => "module_divergence",
);

/// Every published graph vocabulary is the whole variant set, in order, and
/// every token it claims is the token serde writes.
///
/// One case over the four, because they are one claim. The registry builds a
/// single tool schema out of all four arrays, and a token a client may send that
/// the schema never advertised is the same break whichever vocabulary grew the
/// variant.
#[test]
fn every_graph_vocabulary_publishes_its_variants_and_wire_tokens() {
    assert_edge_kinds_published();
    assert_edge_certainties_published();
    assert_relation_directions_published();
    assert_analysis_modes_published();
}
