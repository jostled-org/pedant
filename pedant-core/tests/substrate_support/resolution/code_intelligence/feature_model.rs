//! The closed `pedant-snippet` feature table, written down.
//!
//! The features are the whole selection surface of the code-intelligence
//! product: which languages a build parses, which graph producers it links, and
//! — by what they never name — which parts of the linter it cannot reach. A
//! table read out of the manifest would agree with whatever the manifest says,
//! so it could not reject a tenth feature, a language that quietly became
//! unconditional, or a forwarding entry that reached the judgment surface.

/// One `pedant-snippet` feature and the exact set it selects.
pub(crate) struct FeatureRow {
    /// The feature name a consumer selects.
    pub(crate) feature: &'static str,
    /// Everything it turns on, in manifest order.
    pub(crate) selects: &'static [&'static str],
}

/// The complete `[features]` table, closed.
///
/// `default` is the installed binary's selection: all six supported languages
/// and both graph producers. Every other row is one language or one graph
/// producer, so a library consumer names the profile it wants.
pub(crate) const FEATURE_ROWS: &[FeatureRow] = &[
    FeatureRow {
        feature: "default",
        selects: &[
            "lang-rust",
            "lang-go",
            "lang-javascript",
            "lang-typescript",
            "lang-python",
            "lang-bash",
            "graph-rust",
            "graph-go",
        ],
    },
    FeatureRow {
        feature: "lang-rust",
        selects: &["pedant-syntax/rust"],
    },
    FeatureRow {
        feature: "lang-go",
        selects: &["pedant-syntax/ts-go"],
    },
    FeatureRow {
        feature: "lang-javascript",
        selects: &["pedant-syntax/ts-javascript"],
    },
    FeatureRow {
        feature: "lang-typescript",
        selects: &["pedant-syntax/ts-typescript"],
    },
    FeatureRow {
        feature: "lang-python",
        selects: &["pedant-syntax/ts-python"],
    },
    FeatureRow {
        feature: "lang-bash",
        selects: &["pedant-syntax/ts-bash"],
    },
    FeatureRow {
        feature: "graph-rust",
        selects: &["lang-rust", "dep:pedant-core", "dep:pedant-graph"],
    },
    FeatureRow {
        feature: "graph-go",
        selects: &[
            "lang-go",
            "dep:pedant-core",
            "dep:pedant-graph",
            "pedant-graph/go",
        ],
    },
    FeatureRow {
        feature: "test-support",
        selects: &[],
    },
];

/// The six language features, in the order the closed language table states
/// them.
pub(crate) const LANGUAGE_FEATURES: &[&str] = &[
    "lang-rust",
    "lang-go",
    "lang-javascript",
    "lang-typescript",
    "lang-python",
    "lang-bash",
];

/// The two graph-producer features.
pub(crate) const GRAPH_FEATURES: &[&str] = &["graph-rust", "graph-go"];

/// Feature names no `pedant-snippet` row may select, at any depth of spelling.
///
/// The judgment surface, the semantic tier, rust-analyzer, the proof-only
/// resolution probe, and ECMAScript resolution are all reachable through a
/// single mistyped forwarding entry, and every one of them would link a
/// toolchain or a policy engine into a navigation binary.
pub(crate) const FORBIDDEN_FEATURE_FRAGMENTS: &[&str] = &[
    "checks",
    "semantic",
    "ra_ap",
    "line-index",
    "resolution-test-support",
    "ecmascript",
];
