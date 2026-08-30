//! The written-down dependency boundary `pedant-snippet` states before it holds
//! any index code.
//!
//! Every row here is a claim about a tracked manifest or a tracked script, not
//! a reading of one. A table discovered from the manifest would agree with
//! whatever the manifest happens to say, so it could not reject an edge that
//! widened, dropped its published version, or arrived with no audit behind it.

use pedant_types::Capability;

/// The manifest the code-intelligence product boundary is declared in.
pub(crate) const SNIPPET_MANIFEST: &str = "pedant-snippet/Cargo.toml";

/// The tracked owner of the dependency-closure rows.
pub(crate) const CLOSURE_CHECK: &str =
    ".github/scripts/check_code_intelligence_dependency_closure.sh";

/// The tracked owner of the source-capability profile.
pub(crate) const CAPABILITY_CHECK: &str = ".github/scripts/check_code_intelligence_capabilities.sh";

/// The tracked owner of the first-party syntax capability profile.
///
/// It predates this plan and ranges over the extraction tree beside the product
/// tree, so it is the second owner ruling on what `pedant-snippet/src` may do.
pub(crate) const SYNTAX_CAPABILITY_CHECK: &str = ".github/scripts/check_syntax_capabilities.sh";

/// The tracked owner of the feature-configuration matrix.
pub(crate) const CONFIGURATION_CHECK: &str =
    ".github/scripts/check_code_intelligence_configurations.sh";

/// The lockfile that states which third-party crate versions this product ships.
pub(crate) const WORKSPACE_LOCKFILE: &str = "Cargo.lock";

/// Where `pedant supply-chain` commits one registry crate's audit.
///
/// Auditing a third-party edge means running pedant over the vendored crate,
/// and the attestation it writes beneath this root is the verdict. Reading that
/// file is what keeps the table below from being a claim about itself: a crate
/// admitted without an audit has no attestation to read, so the claim fails
/// rather than passing on the strength of its own enum.
pub(crate) const ATTESTATION_ROOT: &str = ".pedant/baselines/cargo";

/// Every tracked owner that rules on the product tree, and the first-party
/// trees each one must range over.
///
/// The graph and Go resolution trees have their own profiles and no claim over
/// this product. Two owners do reach `pedant-snippet/src`: the code-intelligence
/// checker, whose whole subject is the product tree those substrates are
/// assembled in, and the first-party syntax checker, which covers the extraction
/// tree beside it. The product owner admits reads, hashing, an exit status, and
/// elapsed time. The syntax owner requires an empty profile. Naming each tree
/// once prevents either contract from weakening or widening through a second
/// checker with a different predicate.
pub(crate) const CAPABILITY_PROFILE_OWNERS: &[(&str, &[&str], &str)] = &[
    (
        CAPABILITY_CHECK,
        &["pedant-snippet/src"],
        "assert_only_read_digest_exit_status_and_elapsed_under",
    ),
    (
        SYNTAX_CAPABILITY_CHECK,
        &["pedant-syntax/src"],
        "assert_no_capability_under",
    ),
];

/// What every declared edge states about itself, whatever kind of edge it is.
///
/// A first-party edge and an audited third-party edge are read for different
/// reasons and answer the same two questions: which crate, and exactly which
/// features. One shape means one reader, so the two kinds cannot drift into
/// disagreeing about what "minimum" means.
pub(crate) struct DeclaredEdge {
    /// The crate the edge names.
    pub(crate) package: &'static str,
    /// The exact `default-features` value the edge must state, or `None` when
    /// the package publishes no feature at all and the key would say nothing.
    pub(crate) default_features: Option<bool>,
    /// The exact feature list the edge selects.
    pub(crate) features: &'static [&'static str],
}

/// One first-party edge `pedant-snippet` declares.
pub(crate) struct FirstPartyEdge {
    /// The crate and the exact selection it is taken with.
    pub(crate) edge: DeclaredEdge,
    /// The published version requirement it carries beside its path.
    ///
    /// A path-only edge publishes as a registry dependency with no version,
    /// which `cargo publish` refuses, so the release graph and the working tree
    /// would disagree only at the moment of publication.
    pub(crate) version: &'static str,
    /// The workspace-relative path it resolves through while unpublished.
    pub(crate) path: &'static str,
    /// Whether the edge is selected by a feature rather than always linked.
    pub(crate) optional: bool,
}

/// The four first-party edges the code-intelligence product is built from.
///
/// None of them selects a feature. Every language and graph selection is made
/// by a `pedant-snippet` feature instead, so a library consumer can compile a
/// smaller profile; a language named on the edge would be unconditional for
/// every consumer.
pub(crate) const FIRST_PARTY_EDGES: &[FirstPartyEdge] = &[
    FirstPartyEdge {
        edge: DeclaredEdge {
            package: "pedant-types",
            default_features: None,
            features: &[],
        },
        version: "0.16.0",
        path: "../pedant-types",
        optional: false,
    },
    FirstPartyEdge {
        edge: DeclaredEdge {
            package: "pedant-syntax",
            default_features: Some(false),
            features: &[],
        },
        version: "0.5.0",
        path: "../pedant-syntax",
        optional: false,
    },
    FirstPartyEdge {
        edge: DeclaredEdge {
            package: "pedant-core",
            default_features: Some(false),
            features: &[],
        },
        version: "0.23.0",
        path: "../pedant-core",
        optional: true,
    },
    FirstPartyEdge {
        edge: DeclaredEdge {
            package: "pedant-graph",
            default_features: Some(false),
            features: &[],
        },
        version: "0.4.0",
        path: "../pedant-graph",
        optional: true,
    },
];

/// What one admitted third-party crate is admitted to do.
///
/// The set is closed and holds no write, spawn, or network variant: a crate
/// whose job needs one has no row to state, so it cannot be added to the table
/// without changing this enum in the same commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DependencyCapability {
    /// Reads source bytes from a path the caller supplied.
    SourceRead,
    /// Observes directory contents and change events.
    DirectoryObservation,
    /// Computes a digest over bytes already in memory.
    Hashing,
}

impl DependencyCapability {
    /// The capability a first-party use site of this crate would state.
    ///
    /// The mapping is what connects the written-down table to the tracked
    /// profile: the capability check reads exactly these names out of the
    /// snippet tree, so a row whose crate needed a spawn would have to widen
    /// that profile before it could compile a use site.
    pub(crate) fn stated_capability(self) -> Capability {
        match self {
            Self::SourceRead | Self::DirectoryObservation => Capability::FileRead,
            Self::Hashing => Capability::Crypto,
        }
    }
}

/// The capabilities the admitted closure may state, as a closed set.
pub(crate) const READ_ONLY_CAPABILITIES: &[Capability] =
    &[Capability::FileRead, Capability::Crypto];

/// The capabilities no code-intelligence source may state, and the ones the
/// sentinel proves the production detector still reports.
pub(crate) const FORBIDDEN_CAPABILITIES: &[Capability] = &[
    Capability::FileWrite,
    Capability::ProcessExec,
    Capability::Network,
];

/// One site in an admitted crate's attestation that states a capability this
/// closure otherwise forbids, and the reason the audit admitted it.
///
/// A forbidden finding is not automatically a forbidden crate: a hashing crate
/// that writes a file in its own test module ships no writer, and a watcher that
/// reads its own process identifier spawns nothing. The audit read each of these
/// sites, and this is where what it read is written down.
///
/// The row is matched on the file and the evidence rather than the line, so a
/// patch bump that moves a test module does not rewrite the table while a new
/// spawn, socket, or write the audit never saw still fails it.
pub(crate) struct AcceptedFinding {
    /// The forbidden capability the site states.
    pub(crate) capability: Capability,
    /// The attestation-relative source the site sits in.
    pub(crate) file: &'static str,
    /// The exact symbol pedant named as the evidence.
    pub(crate) evidence: &'static str,
    /// Why the audit admitted it.
    pub(crate) reason: &'static str,
}

/// One third-party crate the code-intelligence runtime admits, and the exact
/// minimum feature selection it is admitted with.
pub(crate) struct AdmittedDependency {
    /// The crate and the exact selection it was audited under.
    pub(crate) edge: DeclaredEdge,
    /// What the crate is admitted to do.
    pub(crate) capability: DependencyCapability,
    /// Every forbidden capability its committed attestation states, and why.
    ///
    /// An empty list is the strongest row of all: the audit found nothing to
    /// admit.
    pub(crate) accepted_findings: &'static [AcceptedFinding],
}

/// The reason a write inside a crate's own tests is not a write this product
/// ships.
///
/// Four of the six accepted sites are this one fact, and one spelling of it
/// keeps them from drifting into disagreeing about what a test module is.
const TEST_SCAFFOLDING: &str = "the crate's own test scaffolding, which no non-test build compiles";

/// The watcher, ignore walker, and digest owner, added before any code consumes
/// them so the closure is audited before it is used.
pub(crate) const ADMITTED_DEPENDENCIES: &[AdmittedDependency] = &[
    AdmittedDependency {
        edge: DeclaredEdge {
            package: "notify",
            default_features: Some(false),
            features: &["macos_kqueue"],
        },
        capability: DependencyCapability::DirectoryObservation,
        accepted_findings: &[
            AcceptedFinding {
                capability: Capability::ProcessExec,
                file: "./src/fsevent.rs",
                evidence: "std::process::id",
                reason: "reading this process's own identifier to tag the events it raised itself, \
                         which starts nothing; the FSEvents backend holding it is deselected here \
                         in favour of macos_kqueue",
            },
            AcceptedFinding {
                capability: Capability::FileWrite,
                file: "./src/fsevent.rs",
                evidence: "tempfile::tempdir",
                reason: TEST_SCAFFOLDING,
            },
            AcceptedFinding {
                capability: Capability::FileWrite,
                file: "./src/inotify.rs",
                evidence: "tempfile::tempdir",
                reason: TEST_SCAFFOLDING,
            },
            AcceptedFinding {
                capability: Capability::FileWrite,
                file: "./src/inotify.rs",
                evidence: "std::fs::create_dir",
                reason: TEST_SCAFFOLDING,
            },
            AcceptedFinding {
                capability: Capability::FileWrite,
                file: "./src/lib.rs",
                evidence: "tempfile::tempdir",
                reason: TEST_SCAFFOLDING,
            },
        ],
    },
    AdmittedDependency {
        edge: DeclaredEdge {
            package: "ignore",
            default_features: Some(false),
            features: &[],
        },
        capability: DependencyCapability::SourceRead,
        accepted_findings: &[AcceptedFinding {
            capability: Capability::FileWrite,
            file: "./src/dir.rs",
            evidence: "std::fs::create_dir_all",
            reason: TEST_SCAFFOLDING,
        }],
    },
    AdmittedDependency {
        edge: DeclaredEdge {
            package: "sha2",
            default_features: Some(false),
            features: &[],
        },
        capability: DependencyCapability::Hashing,
        accepted_findings: &[],
    },
];

/// The transport crates `pedant-snippet` already carried before this plan.
///
/// They are the command tree and the stdio server, not code intelligence, and
/// they are written down so a fourth third-party crate cannot join the closure
/// without being classified as one or the other.
pub(crate) const TRANSPORT_DEPENDENCIES: &[&str] =
    &["clap", "rmcp", "serde", "serde_json", "thiserror", "tokio"];

/// Dependency feature names that would put a write, spawn, or socket surface
/// into the navigation closure.
///
/// `tokio` is the edge this is about: the binary needs `rt` and `time` for the
/// stdio server's shutdown path, and one more entry in the same list would give
/// a read-only product a process spawner or a socket.
pub(crate) const FORBIDDEN_DEPENDENCY_FEATURES: &[&str] =
    &["process", "net", "fs", "signal", "serialization-compat-6"];

/// Crates the navigation closure must never name, whatever a feature says.
///
/// This is the one list. A source scan cannot see a capability that arrives as
/// a dependency and is used through a re-export, so the boundary proof and the
/// source-capability proof both read the `[dependencies]` table — and they read
/// it against these rows. A second copy is a second answer to "what may this
/// product link", and the two copies drift apart in the direction that admits
/// something: each one is blind to whatever the other forbids alone.
pub(crate) const FORBIDDEN_PACKAGES: &[&str] = &[
    "reqwest",
    "ureq",
    "hyper",
    "tempfile",
    "ra_ap_ide",
    "ra_ap_hir",
    "ra_ap_project_model",
    "ra_ap_load-cargo",
    "lsp-types",
    "tower-lsp",
    "pedant-lang",
];
