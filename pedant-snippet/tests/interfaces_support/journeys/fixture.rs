//! The one case authority every transport journey reads.
//!
//! One mixed six-language repository, handed to a spawned CLI and a real stdio
//! server as a root, and indexed once in process to learn the revision and the
//! dense positions. Both transports therefore answer about the same bytes, under
//! the same revision, and the parity journey can compare their answers without
//! either side stating a fact of its own.
//!
//! The one setup two journeys share is here too. Breaking the named authority
//! to force a refused rebuild is three constants and a five-step sequence, and
//! the constants were already unified because two journeys break one file —
//! leaving the sequence that reads them as the half either could quietly start
//! spelling differently.
//!
//! The in-process index is built on the first question that needs one. Six of
//! the fixtures this suite builds only ever point a child at a directory, and an
//! index nobody reads is a second whole-repository parse those journeys paid for
//! and threw away. The descriptor table is built with it, once, because every
//! qualified name a journey names is a search over the same outlines.

use std::cell::OnceCell;

use pedant_snippet::{CodeIntelligenceState, IndexRevision, StructureDescriptor};
use serde_json::Value;

use crate::child::Server;
use crate::failure::Failure;
use crate::index::fixture::Repository;
use crate::index::harness::indexed;
use crate::index::sources::MIXED_REPOSITORY;
use crate::journeys::client;

/// One repository, and the identities its answers are stated in.
///
/// The repository is held because it owns the temporary tree: dropping it
/// removes the directory, and a journey that let it drop while a child was
/// still running would be spawning a server over a root that no longer exists.
pub struct Fixture {
    repository: Repository,
    built: OnceCell<Built>,
    root: Box<str>,
}

/// The index one fixture was read from, and every structure it retained.
///
/// One value rather than two cells: the descriptors are positions inside this
/// state's own revision, so a fixture holding them apart could hand a journey
/// positions from an index it no longer names.
struct Built {
    state: CodeIntelligenceState,
    described: Box<[StructureDescriptor]>,
}

impl Fixture {
    /// Write the mixed six-language repository and hold it.
    pub fn new() -> Self {
        let repository = Repository::of(MIXED_REPOSITORY);
        let root = repository
            .root()
            .to_str()
            .expect("the temporary root has a UTF-8 spelling")
            .into();
        Self {
            repository,
            built: OnceCell::new(),
            root,
        }
    }

    /// The root every child is pointed at.
    pub fn root(&self) -> &str {
        &self.root
    }

    /// The state this fixture's identities were taken from.
    pub fn state(&self) -> &CodeIntelligenceState {
        &self.built().state
    }

    /// The revision every handle in this fixture carries.
    pub fn revision(&self) -> IndexRevision {
        self.built().state.index().revision()
    }

    /// The revision as a transport spells it.
    ///
    /// `Box<str>`, because a caller spells one revision into command lines and
    /// tool arguments and never appends to it.
    pub fn revision_text(&self) -> Box<str> {
        self.revision().to_string().into_boxed_str()
    }

    /// The dense position of the one structure whose qualified name is this.
    ///
    /// A panic rather than an option: every name a journey names is one this
    /// fixture's own sources declare, so a miss is a fixture that stopped
    /// stating the case rather than a repository without the declaration.
    pub fn structure(&self, qualified_name: &str) -> u32 {
        self.built()
            .described
            .iter()
            .find(|structure| structure.qualified_name() == qualified_name)
            .map(|structure| structure.handle().id().position())
            .unwrap_or_else(|| panic!("the fixture declares {qualified_name}"))
    }

    /// The dense position of the one project whose unit label is this.
    pub fn project(&self, unit: &str) -> u32 {
        self.built()
            .state
            .index()
            .projects()
            .iter()
            .find(|slice| slice.key().unit() == unit)
            .map(|slice| slice.id().position())
            .unwrap_or_else(|| panic!("the fixture resolves the {unit} project"))
    }

    /// Write one file into the live tree, for a journey that changes it.
    pub fn write(&self, path: &str, contents: &str) {
        self.repository.write(path, contents);
    }

    /// This fixture's index and descriptor table, built on the first question
    /// that needs them.
    fn built(&self) -> &Built {
        self.built.get_or_init(|| {
            let state = indexed(&self.repository);
            let described = describe(&state);
            Built { state, described }
        })
    }
}

/// Every structure one index retained, described.
///
/// Taken through the public outline of every admitted source rather than off the
/// index's own records, so the positions a journey hands a transport are the
/// positions that transport will answer about.
fn describe(state: &CodeIntelligenceState) -> Box<[StructureDescriptor]> {
    state
        .index()
        .files()
        .iter()
        .flat_map(|file| {
            state
                .outline_file(file.path())
                .unwrap_or_else(|error| panic!("{} outlines: {error}", file.path()))
                .into_result()
                .structures()
                .to_vec()
        })
        .collect()
}

/// The Rust library function both Cargo targets reach.
pub const RUST_MAKE: &str = "crate-a/src/lib.rs::make";

/// The Rust binary entry point that calls it.
pub const RUST_MAIN: &str = "crate-a/src/main.rs::main";

/// The Go constructor in the main module.
pub const GO_NEW: &str = "main.go::New";

/// A Python function, which no resolver in this build covers.
pub const PYTHON_BUILD: &str = "scripts/tool.py::build";

/// The Cargo library target every graph journey selects.
pub const RUST_LIBRARY_UNIT: &str = "crate-a::lib::crate_a";

/// The Cargo binary target that links it.
pub const RUST_BINARY_UNIT: &str = "crate-a::bin::crate-a";

/// The manifest a caller names, so a refusal to load it is the caller's own.
///
/// Stated here beside the other named identities because two live journeys break
/// this same manifest the same way to force the same refused rebuild, and two
/// copies of the three constants are two places for one of them to start
/// breaking a different file.
pub const NAMED_AUTHORITY: &str = "crate-a/Cargo.toml";

/// How that authority is spelled on the command line.
pub const NAMED_PROJECT: &str = "rust:crate-a/Cargo.toml";

/// Bytes no Cargo manifest parses, written where the named authority was.
pub const UNPARSABLE: &str = "[package\nname =\n";

/// The health a refused rebuild publishes, waited for rather than slept through.
///
/// Published beside the sequence that waits for it, because a journey that then
/// waits for the health to *leave* it has to name the same word: the recovery
/// wait is only a claim if the status it recovers to is not this one.
pub const STALE: &str = "stale";

/// The command line every journey that watches one whole root spawns.
///
/// Beside [`named_project_arguments`] and for its reason: the root is the one
/// token in this vector that has to be the fixture's own, and a copy that
/// spelled it from anywhere else would serve a tree no case wrote.
pub fn root_arguments(fixture: &Fixture) -> [&str; 3] {
    ["mcp", "--root", fixture.root()]
}

/// The command line a journey that breaks the named authority spawns.
///
/// Naming the project on the command line is what makes its refusal fatal
/// rather than one degraded scope: the caller asked for that project, so an
/// index that quietly dropped it would answer a different question than the one
/// it was started for. Two journeys rest on that, and a second spelling of the
/// argument vector is a second chance for one of them to stop naming it.
pub fn named_project_arguments(fixture: &Fixture) -> [&str; 5] {
    ["mcp", "--root", fixture.root(), "--project", NAMED_PROJECT]
}

/// The two states one refused rebuild is observed through.
pub struct Stale {
    /// What the server answered before the authority was broken.
    pub opened: Value,
    /// The first answer that reported the refused rebuild.
    pub stale: Value,
}

/// Open a session, break the named authority, and wait for the staleness.
///
/// Both journeys that need a refused rebuild reach it the same way: shake
/// hands, probe, overwrite the manifest, wait for the stale health, and require
/// the count of scopes answering from before the change to be a real one. The
/// three constants above were already unified because two journeys break one
/// file; this is the sequence that reads them, unified for the same reason.
///
/// The opening state comes back beside the stale one, because a caller asking
/// what a refused rebuild kept has to hold what it had before.
pub async fn broken_authority_goes_stale(
    server: &mut Server,
    fixture: &Fixture,
) -> Result<Stale, Failure> {
    client::initialized(server).await?;
    let (opened, _) = client::opened(server, "the opening state").await?;
    fixture.write(NAMED_AUTHORITY, UNPARSABLE);
    let stale = client::healthy(server, STALE, "the refused rebuild").await?;
    let scopes = stale["health"]["stale_scopes"].as_u64().unwrap_or(0);
    client::claimed(scopes > 0, || {
        format!(
            "the watcher's refusal reaches the transport, counting every scope \
             now answering from before the change: {}",
            stale["health"]
        )
    })?;
    Ok(Stale { opened, stale })
}
