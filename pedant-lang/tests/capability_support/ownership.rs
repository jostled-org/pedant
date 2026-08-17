//! One parse session per structured source analysis, proven from this crate's
//! own tracked source.
//!
//! "This analysis parsed the source once" is a claim about ownership: a second
//! parse can produce identical findings and still be a second parse. So this
//! case reads the crate's modules rather than its output.
//!
//! It scans text rather than a syntax tree, because this crate links no Rust
//! parser in any configuration and gains no dependency to run a test. Every
//! claim below is therefore stated as a token that cannot appear in ordinary
//! prose, and comment lines are dropped before any claim is counted.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Every production source `lib.rs` owns, written out rather than derived.
///
/// [`discover_closure`] finds the same set independently by resolving `mod`
/// declarations, and the two must agree, so a new or moved module fails here
/// instead of arriving unscanned.
const MODULE_INVENTORY: &[&str] = &[
    "analyze.rs",
    "attribution/envelope.rs",
    "attribution/mod.rs",
    "attribution/symbols.rs",
    "bash.rs",
    "go.rs",
    "javascript.rs",
    "lib.rs",
    "manifest.rs",
    "python.rs",
    "string_analysis/c_family.rs",
    "string_analysis/evidence.rs",
    "string_analysis/findings.rs",
    "string_analysis/mod.rs",
    "string_analysis/quoted.rs",
    "string_analysis/validation.rs",
];

/// The four structured backends: each binds one session and hands it on.
///
/// Closed against discovery below rather than trusted: a fifth backend that
/// binds a session or seals one is required to be listed here, so it cannot
/// escape the per-backend counts by simply not being named.
const STRUCTURED_BACKENDS: &[&str] = &["bash.rs", "go.rs", "javascript.rs", "python.rs"];

/// The owners that must stay outside structured attribution entirely.
///
/// A manifest states hooks rather than callables, and a direct `Language::Rust`
/// request belongs to `pedant-core`, so neither may reach a parser.
const UNATTRIBUTED_OWNERS: &[&str] = &["analyze.rs", "manifest.rs"];

/// The one module that turns a bound session into symbol profiles.
const PROJECTION_MODULE: &str = "attribution/symbols.rs";

/// The bound-parse entry point every structured backend takes exactly once.
const BOUND_PARSE: &str = "parse_bound(";

/// The raw parse entry points no module in this crate may take.
///
/// `parse_bound(` does not contain `parse(`, so the two counts stay disjoint.
const RAW_PARSE_ROUTES: &[&str] = &["parse(", "Parser", "root_node("];

/// The one call that hands a backend's own session to attribution.
const SEAL_CALL: &str = "attribution::symbols::seal(bound";

/// The one signature that carries a session back out of detection.
const SESSION_RETURN: &str = "-> Option<ParsedSyntax<'source>>";

/// The one question a bound session answers for attribution.
///
/// It is the batch form: every finding's location goes over in one call, so the
/// source is indexed once and its tree walked once per analysis rather than
/// once per finding.
const ANCHOR_QUERY: &str = "enclosing_unit_anchors(";

/// Routes no module in this crate may name.
///
/// Each token is spelled so it cannot collide with this crate's own vocabulary:
/// `Capability::ProcessExec` and `PROCESS_EXEC_COMMAND_PATTERNS` are detection
/// data, not process invocation, and neither contains any token below.
const FORBIDDEN_ROUTES: &[&str] = &[
    // file read
    "std::fs",
    "File::open",
    "read_to_string",
    "read_dir",
    // process
    "std::process",
    "Command::new",
    "Stdio",
    // project model
    "RustProject",
    "project_shape",
    "FileShape",
    // semantic
    "SemanticContext",
    "check_reachability",
    "DataFlowFact",
];

/// 4.T12 (Invariants 9 and 17): the production module universe is exactly the
/// hand-written inventory, each structured backend binds one session and hands
/// that same session to attribution, and no module reaches a raw parser, a
/// file, a project, a process, or a semantic route.
#[test]
fn structured_analyzers_use_one_bound_parse_session() {
    let closure = discover_closure();
    assert!(
        !closure.is_empty(),
        "the production module universe must not be empty"
    );
    let discovered: Box<[&str]> = closure.keys().map(|label| &**label).collect();
    assert_eq!(
        &*discovered, MODULE_INVENTORY,
        "the discovered module universe must equal the hand-written inventory"
    );

    assert_backends_bind_one_session(&closure);
    assert_projection_consumes_the_same_session(&closure);
    assert_unattributed_owners_stay_out(&closure);
    assert_no_raw_parser_or_forbidden_route(&closure);
}

/// The backends are exactly the modules that bind and seal a session, and each
/// binds one and hands that one on.
///
/// The two derived sets close the hand-written list: a fifth backend added to
/// the crate arrives in both of them and fails here, rather than skipping every
/// count below because nobody added its name.
fn assert_backends_bind_one_session(closure: &Closure) {
    assert_eq!(
        &*members_naming(closure, BOUND_PARSE),
        STRUCTURED_BACKENDS,
        "the modules that bind a parse session must be exactly the structured backends"
    );
    assert_eq!(
        &*members_naming(closure, SEAL_CALL),
        STRUCTURED_BACKENDS,
        "the modules that hand a session to attribution must be exactly the structured backends"
    );

    for backend in STRUCTURED_BACKENDS {
        let code = member(closure, backend);
        assert_eq!(
            code.occurrences(BOUND_PARSE),
            1,
            "{backend} must bind exactly one parse session"
        );
        assert_eq!(
            code.occurrences(SESSION_RETURN),
            1,
            "{backend} must return that session from detection exactly once"
        );
        assert_eq!(
            code.occurrences(SEAL_CALL),
            1,
            "{backend} must hand its own session to attribution exactly once"
        );
        assert_eq!(
            code.occurrences(ANCHOR_QUERY),
            0,
            "{backend} must not ask a declaration question itself"
        );
    }
}

/// The projection asks the handed-over session, and parses nothing.
fn assert_projection_consumes_the_same_session(closure: &Closure) {
    let projection = member(closure, PROJECTION_MODULE);
    assert_eq!(
        projection.occurrences(ANCHOR_QUERY),
        1,
        "{PROJECTION_MODULE} must ask the bound session for anchors in one place"
    );
    assert_eq!(
        projection.occurrences(BOUND_PARSE),
        0,
        "{PROJECTION_MODULE} must bind no parse session of its own"
    );

    assert_eq!(
        &*members_naming(closure, ANCHOR_QUERY),
        &[PROJECTION_MODULE],
        "only {PROJECTION_MODULE} may ask a session for an anchor"
    );
}

/// Every discovered module whose code names `token`, in path order.
fn members_naming<'closure>(closure: &'closure Closure, token: &str) -> Box<[&'closure str]> {
    closure
        .iter()
        .filter(|(_, code)| code.occurrences(token) > 0)
        .map(|(label, _)| &**label)
        .collect()
}

/// The manifest and direct-Rust owners reach no parser and no attribution.
fn assert_unattributed_owners_stay_out(closure: &Closure) {
    for owner in UNATTRIBUTED_OWNERS {
        let code = member(closure, owner);
        for route in [BOUND_PARSE, SEAL_CALL, ANCHOR_QUERY, "ParsedSyntax"] {
            assert_eq!(
                code.occurrences(route),
                0,
                "{owner} must stay outside structured attribution, but names `{route}`"
            );
        }
    }
}

/// No module takes a raw parse route or reaches outside the source string.
fn assert_no_raw_parser_or_forbidden_route(closure: &Closure) {
    let mut offenders: Vec<Box<str>> = Vec::new();
    for (label, code) in closure {
        for route in RAW_PARSE_ROUTES.iter().chain(FORBIDDEN_ROUTES) {
            if code.occurrences(route) > 0 {
                offenders.push(format!("{label}: {route}").into_boxed_str());
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "no module may name a raw parser, file, process, project, or semantic route: {offenders:?}"
    );
}

// ---------------------------------------------------------------------------
// Module discovery and scanning
// ---------------------------------------------------------------------------

/// Every discovered production source, keyed by its path under `src/`.
type Closure = BTreeMap<Box<str>, Code>;

/// One source with its comment lines removed.
///
/// Every claim above counts tokens, and a doc comment naming `parse_bound` is
/// prose rather than a call, so the comments come out before anything is
/// counted. Filled once at construction and only ever read afterwards, so it
/// owns exactly the bytes it holds.
struct Code(Box<str>);

impl Code {
    fn read(path: &Path) -> Self {
        let source = std::fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("{} should be readable: {error}", path.display()));
        let mut code = String::with_capacity(source.len());
        for line in source.lines().filter(|line| !is_comment(line)) {
            code.push_str(line);
            code.push('\n');
        }
        Self(code.into_boxed_str())
    }

    fn occurrences(&self, token: &str) -> usize {
        self.0.matches(token).count()
    }
}

/// Whether a line is a line comment, in any of the three spellings.
fn is_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//")
}

fn member<'closure>(closure: &'closure Closure, label: &str) -> &'closure Code {
    closure
        .get(label)
        .unwrap_or_else(|| panic!("{label} should be part of the discovered closure"))
}

/// Every production source `lib.rs` reaches, by resolving `mod` declarations.
///
/// A declaration that names no file is a refusal, not a skip: an unresolved
/// module would silently drop whatever it holds out of every scan above.
fn discover_closure() -> Closure {
    let mut closure: Closure = BTreeMap::new();
    let mut pending = vec![crate_source().join("lib.rs")];
    while let Some(path) = pending.pop() {
        let label = relative_to_source(&path);
        if closure.contains_key(&label) {
            continue;
        }
        let code = Code::read(&path);
        for name in declared_modules(&code, &path).iter() {
            let child = resolve_module(&path, name)
                .unwrap_or_else(|| panic!("`mod {name};` in {} names no file", path.display()));
            pending.push(child);
        }
        closure.insert(label, code);
    }
    closure
}

/// The names of every non-inline `mod` declaration in one source.
///
/// An inline `mod name { … }` body is already part of its file, so it adds no
/// member and its opening brace keeps it out of this scan.
///
/// A line that states a `mod` declaration this scanner cannot name is a
/// refusal, not a skip, for the same reason an unresolvable `mod` is: a
/// trailing comment or a same-line attribute would otherwise drop the module
/// and everything it holds out of every scan above, while the hand-written
/// inventory still matched.
fn declared_modules(code: &Code, path: &Path) -> Box<[Box<str>]> {
    code.0
        .lines()
        .map(str::trim)
        .filter(|line| declares_module(line))
        .map(|line| {
            module_name(line).unwrap_or_else(|| {
                panic!(
                    "`{line}` in {} states a module this scan cannot name",
                    path.display()
                )
            })
        })
        .collect()
}

/// Whether a line states a file-backed `mod` declaration in any spelling.
///
/// Deliberately wider than [`module_name`] accepts: this is the net that turns
/// a declaration the namer cannot read into a failure rather than a silence.
fn declares_module(line: &str) -> bool {
    line.contains("mod ") && line.ends_with(';')
}

/// The module a `mod name;` line declares, whatever its visibility.
fn module_name(line: &str) -> Option<Box<str>> {
    let name = strip_visibility(line.strip_suffix(';')?)
        .strip_prefix("mod ")?
        .trim();
    let plain = !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_');
    plain.then(|| Box::from(name))
}

/// A declaration with any leading `pub` or `pub(...)` removed.
fn strip_visibility(declaration: &str) -> &str {
    match declaration.strip_prefix("pub") {
        Some(rest) => rest
            .trim_start_matches(|character| character != ' ')
            .trim_start(),
        None => declaration,
    }
}

/// The file a `mod name;` declaration inside `owner` selects.
fn resolve_module(owner: &Path, name: &str) -> Option<PathBuf> {
    let directory = match owner.file_name().and_then(|name| name.to_str()) {
        Some("lib.rs" | "mod.rs") => owner.parent()?.to_path_buf(),
        _ => owner.with_extension(""),
    };
    let flat = directory.join(format!("{name}.rs"));
    let nested = directory.join(name).join("mod.rs");
    match (flat.is_file(), nested.is_file()) {
        (true, _) => Some(flat),
        (_, true) => Some(nested),
        _ => None,
    }
}

fn crate_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn relative_to_source(path: &Path) -> Box<str> {
    path.strip_prefix(crate_source())
        .unwrap_or_else(|_| panic!("{} should sit under src/", path.display()))
        .to_string_lossy()
        .replace('\\', "/")
        .into_boxed_str()
}
