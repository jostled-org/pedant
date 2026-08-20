//! The build predicates a snapshotted Go source carries, and the file facts
//! that state them.
//!
//! Go decides which files a build compiles from four places: the constraint
//! comments above a package clause, the platform terms a file name ends with,
//! whether the name ends `_test.go`, and whether the file imports the
//! pseudo-package the foreign-function bridge is written against. All four are
//! retained here unevaluated. Which of them a particular machine would admit is
//! not asked: this module reads no environment, no target triple, and no
//! toolchain setting, so one repository state states one source universe on
//! every host.

use pedant_syntax::go::{GoBuildConditionKind, GoFileFacts};

/// The suffix that makes a Go file part of its package's test context.
const TEST_SUFFIX: &str = "_test";

/// The pseudo-import that states the foreign-function condition.
const FOREIGN_IMPORT: &str = "C";

/// Every operating-system term a Go file name may end with.
///
/// A written-down table rather than a host lookup: the point of the predicate
/// is that it is retained without being evaluated, and any value read from the
/// running process would make one repository state produce two source
/// universes.
const PLATFORM_SYSTEMS: &[&str] = &[
    "aix",
    "android",
    "darwin",
    "dragonfly",
    "freebsd",
    "hurd",
    "illumos",
    "ios",
    "js",
    "linux",
    "nacl",
    "netbsd",
    "openbsd",
    "plan9",
    "solaris",
    "wasip1",
    "windows",
    "zos",
];

/// Every instruction-set term a Go file name may end with.
const PLATFORM_ARCHITECTURES: &[&str] = &[
    "386",
    "amd64",
    "amd64p32",
    "arm",
    "arm64",
    "arm64be",
    "armbe",
    "loong64",
    "mips",
    "mips64",
    "mips64le",
    "mips64p32",
    "mips64p32le",
    "mipsle",
    "ppc",
    "ppc64",
    "ppc64le",
    "riscv",
    "riscv64",
    "s390",
    "s390x",
    "sparc",
    "sparc64",
    "wasm",
];

/// One unevaluated reason a Go source may not be part of every build.
///
/// A predicate is evidence, never a decision. A consumer that needs to know
/// whether two conditioned declarations can both exist says "possible" rather
/// than picking one, because this tier never learns which build is running.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GoBuildCondition {
    /// A constraint comment above the package clause, kept verbatim.
    Stated {
        /// Which spelling states the constraint.
        kind: GoBuildConditionKind,
        /// The constraint text, without its directive prefix.
        constraint: Box<str>,
    },
    /// An operating-system or instruction-set term the file name ends with.
    PlatformSuffix {
        /// The term itself, exactly as the file name spells it.
        term: Box<str>,
    },
    /// The file belongs to its package's test context.
    TestContext,
    /// The file imports the foreign-function pseudo-package.
    ForeignFunctions,
}

impl GoBuildCondition {
    /// The stable token this predicate takes in a digest or a rendering.
    ///
    /// One spelling, stated once: the fingerprint hashes these tokens and a
    /// proof renders them, so a predicate cannot be covered by the digest under
    /// one text and reported under another.
    pub fn token(&self) -> Box<str> {
        match self {
            Self::Stated { kind, constraint } => {
                format!("stated:{}:{constraint}", stated_token(*kind)).into_boxed_str()
            }
            Self::PlatformSuffix { term } => format!("suffix:{term}").into_boxed_str(),
            Self::TestContext => Box::from("test"),
            Self::ForeignFunctions => Box::from("foreign"),
        }
    }
}

/// The stable token one constraint spelling takes.
fn stated_token(kind: GoBuildConditionKind) -> &'static str {
    match kind {
        GoBuildConditionKind::GoBuild => "directive",
        GoBuildConditionKind::LegacyBuildTag => "legacy",
    }
}

/// Whether a file name puts its source in the package's test context.
pub(super) fn is_test_source(name: &str) -> bool {
    stem(name).ends_with(TEST_SUFFIX)
}

/// Every predicate one source carries, in the order they are stated: the
/// constraint comments first, then the file name's platform terms, then the
/// test context, then the foreign-function bridge.
pub(super) fn conditions_of(name: &str, facts: &GoFileFacts<'_>) -> Box<[GoBuildCondition]> {
    let mut stated: Vec<GoBuildCondition> = facts
        .build_conditions()
        .iter()
        .map(|condition| GoBuildCondition::Stated {
            kind: condition.kind(),
            constraint: Box::from(condition.constraint()),
        })
        .collect();
    stated.extend(platform_suffixes(name));
    stated.extend(is_test_source(name).then_some(GoBuildCondition::TestContext));
    stated.extend(imports_foreign_bridge(facts).then_some(GoBuildCondition::ForeignFunctions));
    stated.into_boxed_slice()
}

/// The platform terms one file name ends with.
///
/// Go reads at most two: a trailing instruction-set term may be preceded by an
/// operating-system term, and a single trailing term may be either. The test
/// suffix is removed first, so `parse_linux_test.go` is a Linux file in the
/// test context rather than a file about a platform named `test`.
fn platform_suffixes(name: &str) -> Box<[GoBuildCondition]> {
    let stem = stem(name);
    let base = stem.strip_suffix(TEST_SUFFIX).unwrap_or(stem);
    let tail = base.rsplit('_').next().unwrap_or_default();
    let leading = base.strip_suffix(tail).unwrap_or_default();
    trailing_terms(leading, tail)
        .into_iter()
        .map(|term| GoBuildCondition::PlatformSuffix {
            term: Box::from(term),
        })
        .collect()
}

/// The platform terms one file name's trailing segments state.
///
/// An instruction-set term may be preceded by an operating-system one, and a
/// lone trailing term may be either. A trailing segment that names neither
/// states no predicate, so `zz_generated.go` is an ordinary source.
fn trailing_terms<'name>(leading: &'name str, tail: &'name str) -> Vec<&'name str> {
    match (
        PLATFORM_ARCHITECTURES.contains(&tail),
        PLATFORM_SYSTEMS.contains(&tail),
    ) {
        (true, _) => system_before(leading)
            .into_iter()
            .chain(std::iter::once(tail))
            .collect(),
        (false, true) => vec![tail],
        (false, false) => Vec::new(),
    }
}

/// The operating-system term written before an instruction-set term.
fn system_before(leading: &str) -> Option<&str> {
    let previous = leading.strip_suffix('_')?.rsplit('_').next()?;
    PLATFORM_SYSTEMS.contains(&previous).then_some(previous)
}

/// Whether a source imports the foreign-function pseudo-package.
fn imports_foreign_bridge(facts: &GoFileFacts<'_>) -> bool {
    facts
        .imports()
        .iter()
        .any(|import| import.path() == FOREIGN_IMPORT)
}

/// One Go file name without its extension.
fn stem(name: &str) -> &str {
    name.strip_suffix(".go").unwrap_or(name)
}
