//! The boundary between Cargo tests and local lifecycle authority.
//!
//! GitHub checks out tracked repository files. Local plan tooling also creates
//! ignored manifests, documents, and logs. A Cargo test that reads one of those
//! files passes locally and fails only in CI, so test source must not name one
//! as a constant or direct file-read argument.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, ItemConst, ItemStatic};

use crate::repository_artifact_literals::string_literals;
use crate::resolution::test_identity::workspace_test_sources;

/// Every call this scan reads as a file read.
///
/// The workspace's own readers are named beside the standard-library ones,
/// because they are what a Cargo test actually opens a repository file with:
/// `read_text` is the one shared tracked-file reader and `manifest_table`
/// parses what it returns. A table that named only `std` would leave every
/// structural claim in this repository free to read a lifecycle artifact.
///
/// Every name is required to match at least one call the workspace tests make.
/// A dead arm is how this scan goes blind: the table once named a reader the
/// tree had renamed away, so the walk read no call site at all and reported the
/// boundary held. The packaged-workspace tree used to carry a second reader of
/// its own, and it was admitted here as a fourth name; it now reads through
/// `read_text` like every other structural claim.
const FILE_READERS: &[&str] = &[
    "manifest_table",
    "open",
    "read",
    "read_text",
    "read_to_string",
];

#[test]
fn cargo_tests_do_not_depend_on_local_lifecycle_artifacts() {
    let reading = artifact_reading();
    assert!(
        reading.violations.is_empty(),
        "Cargo tests must not name local lifecycle artifacts: {:?}",
        reading.violations
    );
    let unmatched: Box<[&str]> = FILE_READERS
        .iter()
        .copied()
        .filter(|reader| !reading.readers.contains(reader))
        .collect();
    assert!(
        unmatched.is_empty(),
        "every admitted reader must name a call the workspace tests make, or the scan is \
         blind to it: {unmatched:?}"
    );
}

/// Every Cargo test site that names a local lifecycle artifact.
///
/// The scan rather than the assertion, because the completed-product inventory
/// states the same boundary as part of what this repository ships. One
/// implementation, two registered owners: a second walk could pass one while the
/// other drifted into reading a smaller set of roots.
///
/// The universe is the process-wide workspace test reading. Every member's
/// `tests/` tree is walked and read once for this executable, and a second walk
/// here would be a second set for the same claim to drift into.
///
/// Borrowed from the one reading rather than copied out of it, so the two
/// owners state the same set by construction as well as by intent.
pub(crate) fn local_lifecycle_violations() -> &'static [Box<str>] {
    &artifact_reading().violations
}

/// What one walk over the workspace tests found: the artifacts they name, and
/// the readers they call.
///
/// Both halves come from one reading. A reader inventory taken separately could
/// range over a set the violation scan never saw, which is the drift the second
/// half exists to reject.
struct ArtifactReading {
    violations: Vec<Box<str>>,
    readers: BTreeSet<&'static str>,
}

/// That one walk, taken once for the process.
///
/// Two owners ask for it — the case below and the completed-product inventory —
/// and the walk parses every source of every member's `tests/` tree with `syn`.
/// Running it per caller paid for several hundred parses twice over to reach
/// the same answer.
fn artifact_reading() -> &'static ArtifactReading {
    static READING: OnceLock<ArtifactReading> = OnceLock::new();
    READING.get_or_init(scan_workspace_tests)
}

fn scan_workspace_tests() -> ArtifactReading {
    let mut reading = ArtifactReading {
        violations: Vec::new(),
        readers: BTreeSet::new(),
    };
    for source in workspace_test_sources() {
        let (path, text) = (&source.path, &source.text);
        let scanned = scan_source(path, text);
        reading.violations.extend(scanned.violations);
        reading.readers.extend(scanned.readers);
    }
    reading
}

fn scan_source(relative: &str, text: &str) -> ArtifactReading {
    let syntax =
        syn::parse_file(text).unwrap_or_else(|error| panic!("{relative} should parse: {error}"));
    let mut scanner = LocalArtifactScanner::new(relative);
    scanner.visit_file(&syntax);
    scanner.finish()
}

/// The walk that produces one [`ArtifactReading`].
struct LocalArtifactScanner<'path> {
    source: &'path str,
    violations: Vec<Box<str>>,
    readers: BTreeSet<&'static str>,
}

impl<'path> LocalArtifactScanner<'path> {
    fn new(source: &'path str) -> Self {
        Self {
            source,
            violations: Vec::new(),
            readers: BTreeSet::new(),
        }
    }

    /// What this walk found, once it is over.
    ///
    /// Minted by the scanner rather than assembled from its fields at the call
    /// site. Both halves of a reading have to come from one walk — that is the
    /// whole of what the type is for — and a caller free to name the fields is
    /// a caller free to pair one walk's violations with another walk's readers.
    fn finish(self) -> ArtifactReading {
        ArtifactReading {
            violations: self.violations,
            readers: self.readers,
        }
    }

    fn inspect(&mut self, expression: &Expr, owner: &str) {
        self.violations.extend(
            string_literals(expression)
                .into_iter()
                .filter(|value| is_local_lifecycle_artifact(value))
                .map(|value| format!("{}: {owner} names {value}", self.source).into_boxed_str()),
        );
    }
}

impl<'ast> Visit<'ast> for LocalArtifactScanner<'_> {
    fn visit_item_const(&mut self, item: &'ast ItemConst) {
        self.inspect(&item.expr, &format!("const {}", item.ident));
        visit::visit_item_const(self, item);
    }

    fn visit_item_static(&mut self, item: &'ast ItemStatic) {
        self.inspect(&item.expr, &format!("static {}", item.ident));
        visit::visit_item_static(self, item);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Some(reader) = file_reader(&call.func) {
            self.readers.insert(reader);
            for argument in &call.args {
                self.inspect(argument, "direct file read");
            }
        }
        visit::visit_expr_call(self, call);
    }
}

/// Which admitted reader one called path names, if any.
///
/// The matched table entry is returned rather than a boolean, so the same walk
/// that reads the arguments also records which readers the workspace reaches.
fn file_reader(expression: &Expr) -> Option<&'static str> {
    match expression {
        Expr::Path(path) => path.path.segments.last().and_then(|segment| {
            let called = segment.ident.to_string();
            FILE_READERS.iter().copied().find(|name| *name == called)
        }),
        _ => None,
    }
}

/// The local manifest a plan run writes, spelled in pieces.
///
/// Never as one literal: this scan reads the workspace's own test sources, and a
/// constant here holding the whole name is the first thing it would refuse.
/// Joined once for the process, because the check below runs against every
/// string literal of every source the walk parses.
fn local_manifest() -> &'static str {
    static NAME: OnceLock<String> = OnceLock::new();
    NAME.get_or_init(|| [".", "manifest", ".toml"].concat())
}

fn is_local_lifecycle_artifact(value: &str) -> bool {
    let first = value.split('/').next();
    value == local_manifest() || matches!(first, Some("docs" | "logs"))
}
