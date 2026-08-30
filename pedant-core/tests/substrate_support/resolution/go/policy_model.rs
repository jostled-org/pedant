//! The repository policy every Go production owner is held to, written down.
//!
//! Only the Go-specific half lives here. The nesting ceiling, the duplicate
//! floor, and the two forbidden-route lists are the repository's rules rather
//! than this language's, so they belong beside the scans that read them —
//! [`crate::resolution::body_nesting`], [`crate::resolution::body_scan`], and
//! [`crate::resolution::source_routes`]. Two copies of "no production source
//! panics" would be two lists one plan could widen without the other.
//!
//! The ceilings are numbers rather than judgements because a structural claim
//! has to be decidable: "one job per function" is a review sentence, and what a
//! parser can answer is how many statements a body states and how deep its
//! control flow nests. Both are stated here so a body that grew past the bar
//! fails on the number rather than on a reviewer noticing.

/// The most statements one Go production body may state.
///
/// Sixteen. The widest body the finished surface states is eleven, so the bar
/// leaves room for one that is genuinely long and still one job, and refuses one
/// that is half again as wide as anything here. `.pedant.toml`'s 80-line body
/// ceiling is the same claim measured in lines, and lines are the weaker
/// measure — a single 60-line match arm reads as one job and a 30-statement body
/// does not. The case also refuses a ceiling that stopped measuring: the widest
/// body it finds must reach past half the bar.
pub const MAX_BODY_STATEMENTS: usize = 16;

/// How far one typed error travels.
#[derive(PartialEq, Eq)]
pub enum ErrorReach {
    /// Out of its crate. A caller elsewhere matches on it, so it must implement
    /// `std::error::Error`.
    Published,
    /// No further than its crate. Every caller maps it into the published error
    /// of the seam that refused, so it states no `Display` of its own and it
    /// must not be `pub` — a neutral cause that escaped would report a Go
    /// failure and a Rust failure as one type.
    Mapped,
}

/// One typed error owner: the source that declares it, the enum, how far it
/// travels, and every variant it states.
pub struct ErrorOwner {
    /// The tracked source, relative to the workspace root.
    pub source: &'static str,
    /// The enum this seam refuses through.
    pub name: &'static str,
    /// Whether callers outside the crate match on it.
    pub reach: ErrorReach,
    /// Every variant, in declaration order.
    pub variants: &'static [&'static str],
}

/// Every seam this plan wrote or changed refuses through its own typed enum.
///
/// Seven seams, seven enums. A seam that borrowed another's error would report
/// a manifest failure as a snapshot failure, and a caller matching on the
/// shared type could not tell which stage refused. The two Rust seams and the
/// graph seam are here because the plan changed them: `RustResolutionError`
/// gained the widened report vocabulary's refusals, `GraphBuildError` gained
/// the neutral projection's, and `RootError` is the neutral cause the plan
/// hoisted out of both loaders.
pub const ERROR_OWNERS: &[ErrorOwner] = &[
    ErrorOwner {
        source: "pedant-core/src/resolution/paths.rs",
        name: "RootError",
        reach: ErrorReach::Mapped,
        variants: &["Unreadable", "NotADirectory"],
    },
    ErrorOwner {
        source: "pedant-core/src/resolution/sites.rs",
        name: "SiteError",
        reach: ErrorReach::Mapped,
        variants: &["UnknownFile", "InvalidCoordinate"],
    },
    ErrorOwner {
        source: "pedant-core/src/resolution/rust/resolve/error.rs",
        name: "RustResolutionError",
        reach: ErrorReach::Published,
        variants: &[
            "UnitMapping",
            "UnitCountMismatch",
            "UnknownFile",
            "UnsupportedDefinitionKind",
            "UnsupportedReferenceKind",
            "InvalidCoordinate",
            "LimitExceeded",
            "ImportsNotConverged",
            "SemanticContextMismatch",
            "SemanticSharedSourceMismatch",
            "Report",
        ],
    },
    ErrorOwner {
        source: "pedant-graph/src/error.rs",
        name: "GraphBuildError",
        reach: ErrorReach::Published,
        variants: &[
            "RootTargetMismatch",
            "SnapshotFingerprintMismatch",
            "MissingUnitBinding",
            "DanglingUnitBinding",
            "SharedUnitBinding",
            "RepeatedUnitContainer",
            "MissingUnitDeclaration",
            "RepeatedUnitDeclaration",
            "SharedUnitRoot",
            "MissingDependencyUnit",
            "MissingSourceNode",
            "RepeatedUnitSource",
            "ReferenceRecordMismatch",
            "MissingDefinitionNode",
            "UnnamedDefinitionKind",
            "UnnamedReferenceKind",
            "MissingReferenceRecord",
            "UnknownContainmentNode",
            "MultiplyContained",
            "UnparentedNode",
            "RootHasParent",
            "ContainmentCycle",
            "CapacityExceeded",
        ],
    },
    ErrorOwner {
        source: "pedant-syntax/src/go/error.rs",
        name: "GoFactError",
        reach: ErrorReach::Published,
        variants: &[
            "LanguageMismatch",
            "SyntaxDepthExceeded",
            "FactCapacityExceeded",
            "DeclarationMapping",
        ],
    },
    ErrorOwner {
        source: "pedant-core/src/resolution/go/error.rs",
        name: "GoProjectError",
        reach: ErrorReach::Published,
        variants: &[
            "InvalidRoot",
            "OutOfRoot",
            "NonUtf8Path",
            "PathRead",
            "ManifestRead",
            "ManifestParse",
            "MissingModuleDeclaration",
            "DuplicateRequirement",
            "DuplicateExclusion",
            "DuplicateReplacement",
            "InvalidVersion",
            "ExcludedRequirement",
            "MissingReplacementManifest",
            "ReplacementModuleMismatch",
            "ConflictingLocalModules",
            "MissingAdmittedModule",
            "ManifestLimitExceeded",
            "DependencyDepthLimitExceeded",
        ],
    },
    ErrorOwner {
        source: "pedant-core/src/resolution/go/snapshot_error.rs",
        name: "GoSnapshotError",
        reach: ErrorReach::Published,
        variants: &[
            "OutOfRoot",
            "NonUtf8Path",
            "PathRead",
            "DirectoryRead",
            "SourceRead",
            "UnnormalizedPath",
            "NonUtf8Source",
            "UnparsedSource",
            "IncompleteSource",
            "MissingPackageClause",
            "AlreadyRefused",
            "StructureProjection",
            "MissingStoredSource",
            "ConflictingPackageClause",
            "FactExtraction",
            "DirectoryEntryLimitExceeded",
            "UnitLimitExceeded",
            "SourceFileLimitExceeded",
            "SourceBytesLimitExceeded",
            "TotalSourceBytesLimitExceeded",
            "RetainedFactsExceeded",
            "RetainedDepthExceeded",
        ],
    },
    ErrorOwner {
        source: "pedant-core/src/resolution/go/resolve/error.rs",
        name: "GoResolutionError",
        reach: ErrorReach::Published,
        variants: &[
            "UnitMapping",
            "UnitCountMismatch",
            "DefinitionMapping",
            "UnknownFile",
            "UnsupportedDefinitionKind",
            "UnsupportedReferenceKind",
            "InvalidCoordinate",
            "CandidateLimitExceeded",
            "InterfaceComparisonLimitExceeded",
            "Report",
        ],
    },
];

/// Variants no fixture can produce, admitted deliberately.
///
/// `GoResolutionError::DefinitionMapping` refuses a lookup miss that the record
/// stage's own construction rules out: Step 6 retains every candidate and
/// enclosing slot as the value `Index::push` returned, so the index it then
/// looks up is one it just wrote. The variant stays because the lookup is
/// fallible in the type system and a future writer may not hold that invariant,
/// and it is named here so the inventory admits it rather than a reader finding
/// it unmatched by any refusal case and deleting it.
///
/// `GoFactError::DeclarationMapping` is the same shape one layer down. The Go
/// walk links a method's receiver to the declaration index its own `admit` just
/// minted against the same inventory, so the lookup cannot miss while that
/// holds. It refuses rather than passing over the miss, because a dropped
/// receiver link leaves the method answering `None` — indistinguishable from a
/// plain function, with no error and nothing red.
pub const DEFENSIVE_ONLY_VARIANTS: &[(&str, &str)] = &[
    ("GoResolutionError", "DefinitionMapping"),
    ("GoFactError", "DeclarationMapping"),
    ("GoProjectError", "MissingAdmittedModule"),
    ("GoSnapshotError", "MissingStoredSource"),
];
