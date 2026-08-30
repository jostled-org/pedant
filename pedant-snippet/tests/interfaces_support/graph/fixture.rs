//! The repository every graph-backed claim is made against, and the handles
//! its declarations are reached by.
//!
//! It is not the mixed six-language repository. That one states one library and
//! one binary, so a declaration in the library has two graph instances — enough
//! to prove that instances are not coalesced, and not enough to page over. This
//! one states a library and [`BINARIES`], so a library declaration appears in
//! one project graph per target and a relation answer is long enough to page
//! over rather than long enough to have a second row.
//!
//! It also states, deliberately: two `run` declarations at different sites, one
//! in a trait and one in the impl that satisfies it, so a join on names would
//! merge them; a second module inside the library, holding one function that
//! calls only out of it and one half of a mutually recursive pair, so the
//! declared partition has both a misplaced symbol and a cycle that crosses it;
//! and a Go module beside the Cargo workspace, so no route crosses from one to
//! the other.
//!
//! The rest of it is there to be refused. One source in each of the four
//! languages this build parses and resolves no project for; a `tsconfig.json`
//! and a `jsconfig.json` beside two of them, so a build that started treating
//! either as a project authority would state graph coverage no extractor has
//! produced yet; and one Cargo package whose manifest no loader can read, so a
//! source a project slice was meant to reach and did not has somewhere to be.

use pedant_snippet::{
    CodeIntelligenceLimits, CodeIntelligenceState, MatchMode, PageRequest, ProjectHandle,
    StructureDescriptor, StructureHandle, SymbolQuery,
};

use crate::index::fixture::Repository;
use crate::index::harness::{built, indexed};
use crate::queries::paging::CEILING;
use crate::queries::support::page;

/// The one library source every graph case names.
///
/// Written once because it is a fact about this fixture rather than about any
/// row: [`repository`] writes the source at this path, and every case that asks
/// a question of a library declaration names the same path back. A second
/// spelling is a row that keeps compiling after the tree moved and answers
/// about a source nothing wrote.
pub const LIBRARY_SOURCE: &str = "graph-lib/src/lib.rs";

/// The key unit of the library's own project graph, on the same terms.
pub const LIBRARY_UNIT: &str = "graph-lib::lib::graph_lib";

/// The one Go source beside the workspace.
pub const GO_SOURCE: &str = "main.go";

/// The key unit of the Go module's project graph.
pub const GO_UNIT: &str = "example.com/graph";

/// The Rust library every project graph in the workspace reaches.
///
/// `Run::run` and the `impl Run for Job` method share a name and a signature and
/// sit at two sites. Nothing else in this source is named twice, so a join that
/// merged them fails here and nowhere else.
///
/// `relay` is the second declared module, and it is there for divergence, which
/// is measured over the declared partition. A crate of one module states one
/// partition, no boundary to cross, and no symbol that could sit anywhere else —
/// so every candidate and every crossing an oracle could disagree about would be
/// one neither side ever held.
///
/// The module carries two declarations, one per claim. `relay::forward` calls
/// nothing but the crate root, so it is the misplaced symbol. `ping` and
/// `relay::pong` call each other, so they are one strongly connected component
/// whose two members are declared in two different partitions — the boundary
/// crossing. Mutual recursion is the only shape that states one: a chain of
/// calls out of a module and back is two components, not one that crosses.
pub const RUST_LIBRARY: &str = "\
pub struct Job {
    id: u32,
}

pub trait Run {
    fn run(&self) -> u32;
}

impl Run for Job {
    fn run(&self) -> u32 {
        self.id
    }
}

pub fn make() -> Job {
    Job { id: 0 }
}

pub fn build() -> u32 {
    make().run()
}

pub fn ping() -> u32 {
    relay::pong()
}

pub mod relay {
    pub fn forward() -> u32 {
        crate::make().run()
    }

    pub fn pong() -> u32 {
        crate::ping()
    }
}
";

/// One binary that links the library and calls into it.
fn binary(name: &str) -> String {
    format!(
        "fn main() {{\n    let _ = graph_lib::build();\n    let _ = {name}();\n}}\n\nfn {name}() -> u32 {{\n    graph_lib::make().run()\n}}\n"
    )
}

/// The Go module beside the workspace, which shares no graph with it.
pub const GO_MAIN: &str = "\
package main

type Job struct {
\tID int
}

func New() *Job {
\treturn &Job{}
}

func (j *Job) Run() int {
\treturn j.ID
}

func main() {
\t_ = New().Run()
}
";

/// One Python source, which this build resolves no project for.
pub const PYTHON_TOOL: &str = "\
def build():
    return 1


class Job:
    def run(self):
        return 1
";

/// One JavaScript source, which this build resolves no project for.
pub const WEB_JAVASCRIPT: &str = "\
export function bundle() {
  return 1;
}

export class Bundler {
  emit() {
    return 1;
  }
}
";

/// One TypeScript source beside it, which this build resolves no project for.
pub const WEB_TYPESCRIPT: &str = "\
export function compile(): number {
  return 1;
}

export class Compiler {
  emit(): number {
    return 1;
  }
}
";

/// One Bash source, which this build resolves no project for.
pub const DEPLOY_SCRIPT: &str = "\
#!/usr/bin/env bash

publish() {
  echo publish
}

publish
";

/// A Cargo manifest no loader can read, so the package it names states no slice.
pub const BROKEN_MANIFEST: &str = "[package\nname = broken\n";

/// The Rust source that package would have compiled.
///
/// Its language resolves projects and builds graphs, and this build resolved no
/// project that reached it — so the absence it states is the failed slice's,
/// not the language's.
pub const STRANDED_LIBRARY: &str = "\
pub fn stranded() -> u32 {
    1
}
";

/// Every source this repository states that no project slice reaches, and the
/// declaration each one is refused through.
pub const SYNTAX_ONLY_SOURCES: &[(&str, &str)] = &[
    ("tool.py", "build"),
    ("web/bundle.js", "bundle"),
    ("web/compile.ts", "compile"),
    ("scripts/publish.sh", "publish"),
    ("broken/src/lib.rs", "stranded"),
];

/// The two configuration files that name no project this build can resolve.
pub const INERT_CONFIGURATIONS: &[&str] = &["web/jsconfig.json", "web/tsconfig.json"];

/// The repository every graph case is indexed over.
pub fn repository() -> Repository {
    let go_module = format!("module {GO_UNIT}\n\ngo 1.22\n");
    let repository = Repository::of(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"graph-lib\"]\nresolver = \"3\"\n",
        ),
        (
            "graph-lib/Cargo.toml",
            "[package]\nname = \"graph-lib\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        (LIBRARY_SOURCE, RUST_LIBRARY),
        ("go.mod", go_module.as_str()),
        (GO_SOURCE, GO_MAIN),
        ("tool.py", PYTHON_TOOL),
        ("web/bundle.js", WEB_JAVASCRIPT),
        ("web/compile.ts", WEB_TYPESCRIPT),
        (
            "web/jsconfig.json",
            "{\n  \"compilerOptions\": { \"checkJs\": true }\n}\n",
        ),
        (
            "web/tsconfig.json",
            "{\n  \"compilerOptions\": { \"strict\": true }\n}\n",
        ),
        ("scripts/publish.sh", DEPLOY_SCRIPT),
        ("broken/Cargo.toml", BROKEN_MANIFEST),
        ("broken/src/lib.rs", STRANDED_LIBRARY),
    ]);
    for name in BINARIES {
        repository.write(&format!("graph-lib/src/bin/{name}.rs"), &binary(name));
    }
    repository
}

/// The binaries that link the library, one project graph each.
///
/// The count is the claim. One neighborhood is answered per project graph that
/// states the seed, so a relation answer over a library declaration is one row
/// per target plus the library's own — and `queries::paging` takes its
/// default-cursor continuation row only over a result that outruns one default
/// page of fifty. A library and three binaries answered four rows, which left
/// that row untaken and this operation's continuation unproven.
///
/// Fifty-one puts the answer at fifty-two: one whole default page, then a
/// remainder that is more than one row, so the second page is a page rather than
/// the last item. `paging` states `outruns_default: true` and
/// `queries::paging::paged_contract_holds` holds that statement against the
/// answer's own length before it takes the row, because a count written down
/// here and a count the index states are two different numbers.
pub const BINARIES: &[&str] = &[
    "link00", "link01", "link02", "link03", "link04", "link05", "link06", "link07", "link08",
    "link09", "link10", "link11", "link12", "link13", "link14", "link15", "link16", "link17",
    "link18", "link19", "link20", "link21", "link22", "link23", "link24", "link25", "link26",
    "link27", "link28", "link29", "link30", "link31", "link32", "link33", "link34", "link35",
    "link36", "link37", "link38", "link39", "link40", "link41", "link42", "link43", "link44",
    "link45", "link46", "link47", "link48", "link49", "link50",
];

/// The repository, indexed under the host defaults.
///
/// The repository is returned with the state because it owns the temporary
/// tree: dropping it removes the directory, and a case that let it drop while
/// still querying would be proving something about a repository that no longer
/// exists.
pub fn indexed_graph() -> (Repository, CodeIntelligenceState) {
    let repository = repository();
    let state = indexed(&repository);
    (repository, state)
}

/// The same repository at a second revision, with one declaration appended.
///
/// The appended source is what makes the two indexes demonstrably different
/// before either one is handed to a row: a handle or a cursor taken from a
/// byte-identical repository would name the same revision and prove nothing.
/// The guard is stated here rather than at each call site, so no caller can take
/// the foreign state without it.
pub fn other_revision(state: &CodeIntelligenceState) -> (Repository, CodeIntelligenceState) {
    let other = repository();
    other.write(
        "graph-lib/src/lib.rs",
        &format!("{RUST_LIBRARY}\npub fn extra() -> u32 {{\n    1\n}}\n"),
    );
    let foreign = indexed(&other);
    assert_ne!(
        foreign.index().revision(),
        state.index().revision(),
        "the two repositories differ, so the two indexes do"
    );
    (other, foreign)
}

/// A repository the caller already owns, indexed again under stated limits.
///
/// The tree is the caller's rather than a fresh one. Writing a second sixteen-
/// file tree and walking the Cargo workspace and the Go module again buys
/// nothing: the ceilings are the only thing that differs, and they are applied
/// at build time rather than written into the sources.
pub fn bounded(repository: &Repository, limits: CodeIntelligenceLimits) -> CodeIntelligenceState {
    built(repository, &[], limits).expect("the graph repository indexes under the stated ceilings")
}

/// Every declaration whose declared name is exactly `name`.
pub fn matching(state: &CodeIntelligenceState, name: &str) -> Box<[StructureDescriptor]> {
    let query = SymbolQuery {
        text: Box::from(name),
        mode: MatchMode::Exact,
        language: None,
        kind: None,
        owner_name: None,
        path_prefix: None,
    };
    state
        .search_symbols(&query, &whole_page())
        .expect("the search answers")
        .into_result()
}

/// The one declaration named `name` in `path`.
pub fn declaration(state: &CodeIntelligenceState, path: &str, name: &str) -> StructureDescriptor {
    let mut found: Vec<StructureDescriptor> = matching(state, name)
        .into_vec()
        .into_iter()
        .filter(|structure| structure.path() == path)
        .collect();
    assert_eq!(
        found.len(),
        1,
        "{path} states exactly one declaration named {name}: {:?}",
        found
            .iter()
            .map(StructureDescriptor::span)
            .collect::<Vec<_>>()
    );
    found.remove(0)
}

/// The handle of the one declaration named `name` in `path`.
pub fn handle(state: &CodeIntelligenceState, path: &str, name: &str) -> StructureHandle {
    declaration(state, path, name).handle()
}

/// The project handle whose key unit is `unit`.
pub fn project(state: &CodeIntelligenceState, unit: &str) -> ProjectHandle {
    let index = state.index();
    let found = index
        .projects()
        .iter()
        .find(|project| project.key().unit() == unit)
        .unwrap_or_else(|| {
            panic!(
                "the repository resolves a project for {unit}: {:?}",
                index
                    .projects()
                    .iter()
                    .map(|project| project.key().unit())
                    .collect::<Vec<_>>()
            )
        });
    ProjectHandle::new(index.revision(), found.id().position())
}

/// Every row is in ascending order, so the answer states one order and not an
/// order the walk happened to produce.
///
/// Stated once because two answers make the claim — an instance set and a
/// neighborhood page — over the same pair of a project position and a node
/// index, and a second copy is how one of them stops asserting it.
pub fn assert_ascending(rows: &[(u32, u32)], why: &str) {
    let mut sorted = rows.to_vec();
    sorted.sort_unstable();
    assert_eq!(rows, sorted.as_slice(), "{why}: {rows:?}");
}

/// One page carrying every item the host admits.
///
/// The size is the shared contract's published [`CEILING`] rather than a second
/// `200` written here. That ceiling is the host's own, and a copy of it in this
/// tree is a second place it has to be revisited.
pub fn whole_page() -> PageRequest {
    page(Some(CEILING), None)
}
