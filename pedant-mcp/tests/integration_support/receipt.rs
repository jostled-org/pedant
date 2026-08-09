//! The completion receipt: what the proof runner must supply, and what the
//! journey must leave behind.
//!
//! The receipt exists so a completion claim cannot be asserted by the thing
//! making it. The runner states an identity — repository root, HEAD, affected
//! package set, terminal summary — and owns a fresh path to write to; the
//! journey answers typed MCP queries against that exact tree and records what
//! it got. Validation then holds the written document to the stated identity.
//!
//! Both halves are checked, and both are checked here rather than in a test
//! body, because the same validator has to serve the ordinary synthetic-input
//! test and the feature-gated final-tree adapter. A second copy could pass one
//! and not the other, which is the failure the receipt is meant to prevent.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The only receipt schema this root writes or accepts.
const RECEIPT_VERSION: u32 = 1;

/// The length of a full git object name.
const SHA_LENGTH: usize = 40;

/// The typed queries a completion receipt must carry for every package in
/// scope, in this order. All three return a JSON array, so a receipt can state
/// how many records each produced without embedding the payload.
pub(crate) const TYPED_TOOLS: [&str; 3] = [
    "query_capabilities",
    "query_gate_verdicts",
    "query_violations",
];

/// Everything the runner states and the journey may not invent.
pub(crate) struct CompletionProofInputs {
    /// The canonical repository root the server is started in.
    pub(crate) root: PathBuf,
    /// The commit the claim is about.
    pub(crate) head_sha: Box<str>,
    /// The exact affected package set, in the order the runner stated it.
    pub(crate) test_scope: Box<[Box<str>]>,
    /// The runner's terminal verification summary.
    pub(crate) terminal_summary: Box<str>,
    /// The directory the runner owns for this invocation's artifacts.
    pub(crate) proof_output_dir: PathBuf,
    /// The unique path beneath [`Self::proof_output_dir`] this run writes.
    pub(crate) receipt_path: PathBuf,
}

impl CompletionProofInputs {
    /// Reject every input the journey could not honestly act on.
    ///
    /// Missing evidence is a failure, never a silent pass: an absent HEAD or an
    /// empty package set would otherwise produce a receipt that validated
    /// against nothing.
    pub(crate) fn validate(&self) -> Result<(), String> {
        check_root(&self.root)?;
        check_sha(&self.head_sha)?;
        check_scope(&self.test_scope)?;
        check_summary(&self.terminal_summary)?;
        check_output_dir(&self.proof_output_dir)?;
        check_receipt_path(&self.receipt_path, &self.proof_output_dir)
    }

    /// Every typed query the journey owes, as `(package, tool)` pairs.
    pub(crate) fn expected_queries(&self) -> Box<[(&str, &'static str)]> {
        self.test_scope
            .iter()
            .flat_map(|package| TYPED_TOOLS.map(|tool| (&**package, tool)))
            .collect()
    }
}

fn check_root(root: &Path) -> Result<(), String> {
    let canonical = root
        .canonicalize()
        .map_err(|error| format!("root {} is not readable: {error}", root.display()))?;
    match (
        canonical.as_path() == root,
        root.join("Cargo.toml").is_file(),
    ) {
        (true, true) => Ok(()),
        (false, _) => Err(format!(
            "root {} is not canonical; {} is",
            root.display(),
            canonical.display()
        )),
        (true, false) => Err(format!("root {} holds no Cargo.toml", root.display())),
    }
}

fn check_sha(head_sha: &str) -> Result<(), String> {
    let shaped = head_sha.len() == SHA_LENGTH
        && head_sha
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    match shaped {
        true => Ok(()),
        false => Err(format!(
            "head_sha {head_sha:?} is not {SHA_LENGTH} lowercase hex digits"
        )),
    }
}

fn check_scope(scope: &[Box<str>]) -> Result<(), String> {
    let mut seen: Vec<&str> = Vec::with_capacity(scope.len());
    for package in scope {
        match (package.trim().is_empty(), seen.contains(&&**package)) {
            (true, _) => return Err(String::from("test_scope holds an empty package name")),
            (_, true) => return Err(format!("test_scope names {package} twice")),
            (false, false) => seen.push(package),
        }
    }
    match seen.is_empty() {
        true => Err(String::from("test_scope names no package")),
        false => Ok(()),
    }
}

fn check_summary(summary: &str) -> Result<(), String> {
    match summary.trim().is_empty() {
        true => Err(String::from("terminal_summary is empty")),
        false => Ok(()),
    }
}

fn check_output_dir(dir: &Path) -> Result<(), String> {
    match dir.is_dir() {
        true => Ok(()),
        false => Err(format!(
            "PROOF_OUTPUT_DIR {} is not a directory",
            dir.display()
        )),
    }
}

fn check_receipt_path(path: &Path, dir: &Path) -> Result<(), String> {
    let named = path.file_name().is_some();
    match (path.starts_with(dir) && named, path.exists()) {
        (true, false) => Ok(()),
        (false, _) => Err(format!(
            "receipt path {} is not a file beneath {}",
            path.display(),
            dir.display()
        )),
        (true, true) => Err(format!(
            "receipt path {} already exists, so it is not unique to this run",
            path.display()
        )),
    }
}

/// One typed query the journey performed, and how much it returned.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub(crate) struct QueryRecord {
    /// The package the query was scoped to.
    pub(crate) package: Box<str>,
    /// The tool that answered it.
    pub(crate) tool: Box<str>,
    /// How many records the tool's JSON array carried.
    pub(crate) results: usize,
}

/// The document the journey writes and validation reads back.
#[derive(Serialize, Deserialize)]
struct Receipt {
    receipt_version: u32,
    root: Box<str>,
    head_sha: Box<str>,
    test_scope: Box<[Box<str>]>,
    terminal_summary: Box<str>,
    queries: Box<[QueryRecord]>,
}

/// Write the receipt for `queries` atomically beneath the runner's directory.
///
/// The rename is the publish: a reader can never observe a half-written
/// document, and a crashed journey leaves no receipt rather than a partial one.
pub(crate) fn write(
    inputs: &CompletionProofInputs,
    queries: Box<[QueryRecord]>,
) -> Result<(), String> {
    let receipt = Receipt {
        receipt_version: RECEIPT_VERSION,
        root: inputs.root.to_string_lossy().into(),
        head_sha: inputs.head_sha.clone(),
        test_scope: inputs.test_scope.clone(),
        terminal_summary: inputs.terminal_summary.clone(),
        queries,
    };
    let body = serde_json::to_string_pretty(&receipt)
        .map_err(|error| format!("the receipt is not serializable: {error}"))?;
    let staged = inputs.receipt_path.with_extension("partial");
    std::fs::write(&staged, body)
        .map_err(|error| format!("cannot write {}: {error}", staged.display()))?;
    std::fs::rename(&staged, &inputs.receipt_path)
        .map_err(|error| format!("cannot publish {}: {error}", inputs.receipt_path.display()))
}

/// Hold the written receipt to the identity the runner stated.
pub(crate) fn validate(inputs: &CompletionProofInputs) -> Result<(), String> {
    let path = &inputs.receipt_path;
    let raw = std::fs::read_to_string(path)
        .map_err(|error| format!("no receipt at {}: {error}", path.display()))?;
    let receipt: Receipt = serde_json::from_str(&raw)
        .map_err(|error| format!("the receipt is not valid JSON: {error} in {raw}"))?;
    check_version(receipt.receipt_version)?;
    check_identity(&receipt, inputs)?;
    check_queries(&receipt.queries, inputs)
}

fn check_version(version: u32) -> Result<(), String> {
    match version == RECEIPT_VERSION {
        true => Ok(()),
        false => Err(format!(
            "the receipt states version {version} rather than {RECEIPT_VERSION}"
        )),
    }
}

fn check_identity(receipt: &Receipt, inputs: &CompletionProofInputs) -> Result<(), String> {
    let root = inputs.root.to_string_lossy();
    let stated = [
        ("root", &*receipt.root, &*root),
        ("head_sha", &receipt.head_sha, &inputs.head_sha),
        (
            "terminal_summary",
            &receipt.terminal_summary,
            &inputs.terminal_summary,
        ),
    ];
    for (field, found, wanted) in stated {
        if found != wanted {
            return Err(format!(
                "the receipt states {field} {found:?} rather than {wanted:?}"
            ));
        }
    }
    match receipt.test_scope == inputs.test_scope {
        true => Ok(()),
        false => Err(format!(
            "the receipt states test_scope {:?} rather than {:?}",
            receipt.test_scope, inputs.test_scope
        )),
    }
}

fn check_queries(queries: &[QueryRecord], inputs: &CompletionProofInputs) -> Result<(), String> {
    let found: Box<[(&str, &str)]> = queries
        .iter()
        .map(|query| (&*query.package, &*query.tool))
        .collect();
    let wanted = inputs.expected_queries();
    if *found != *wanted {
        return Err(format!(
            "the receipt records typed queries {found:?} rather than {wanted:?}"
        ));
    }
    check_answers_are_not_all_empty(queries)
}

/// At least one typed query returned something.
///
/// Every count may legitimately be zero for one package — a type crate reports
/// no capability — but a whole receipt of zeroes is what a server that indexed
/// nothing also produces. Without this the receipt would count its own work and
/// pass whatever that work amounted to.
fn check_answers_are_not_all_empty(queries: &[QueryRecord]) -> Result<(), String> {
    match queries.iter().any(|query| query.results > 0) {
        true => Ok(()),
        false => Err(String::from(
            "every typed query in the receipt returned an empty result, \
             which is what an index that never loaded also reports",
        )),
    }
}
