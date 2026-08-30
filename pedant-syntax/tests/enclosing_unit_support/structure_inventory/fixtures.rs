//! One source per grammar, written to state every structure its language's row
//! of the contract names.
//!
//! Each fixture is the whole of what its language claims, so a row the closed
//! table gains has to be written here before any case can assert it. The
//! expectations live beside the sources rather than inside the cases, because
//! three cases read the same six sources and a table split across them would
//! drift.
//!
//! The Rust row is stated twice in this workspace, once here for the loose
//! `syn` route and once in `pedant-core`'s site inventory for the resolved one.
//! Two recognizers answer it, and neither crate links the other's: `pedant-core`
//! takes `pedant-syntax` with the Go grammar alone. The comparison that binds
//! them is owned by `six_language_outline_is_complete_nested_and_source_exact`
//! at the `pedant-snippet` root, which is the first root that links both.
//!
//! Every row here names its subject. `crate::fixtures` publishes a `Fixture` and
//! a set of `*_SOURCE` constants of its own, for different sources and a
//! different expectation shape, and `model.rs` imports from both in one file —
//! so under the shorter names swapping `super::` for `crate::` still compiled
//! and silently proved a claim about another source.

use pedant_syntax::{StructureKind, SyntaxLanguage};

/// One expected structure: its kind, its declared name, and the position of the
/// structure that owns it.
pub(super) struct Expected {
    pub(super) kind: StructureKind,
    pub(super) name: Option<&'static str>,
    pub(super) owner: Option<u32>,
}

/// One language's fixture: its source, its grammar, every structure that source
/// states in order, and the shallowest ceiling that admits it whole.
pub(super) struct StructureFixture {
    pub(super) language: SyntaxLanguage,
    pub(super) source: &'static str,
    pub(super) expected: &'static [Expected],
    /// The shallowest depth ceiling this source is admitted beneath.
    ///
    /// Written down rather than searched for by running the subject. A depth
    /// derived from the walk under test agrees with that walk by construction:
    /// a walk miscounting every level by the same amount finds its own answer
    /// and reports it as the expectation, so the case beneath it proves only
    /// that some ceiling refuses and some ceiling does not.
    ///
    /// The number is the grammar's own, not the structure table's — Rust counts
    /// `syn` items while the tree-sitter routes count grammar nodes, so a source
    /// stating few structures can still nest deeply. It changes when a fixture's
    /// source changes, which is exactly when a reader should have to restate it.
    pub(super) depth: u32,
}

/// A structure of `kind` named `name`, owned by `owner`.
const fn row(kind: StructureKind, name: Option<&'static str>, owner: Option<u32>) -> Expected {
    Expected { kind, name, owner }
}

pub(super) const STRUCTURE_RUST_SOURCE: &str = "\
pub mod inner {
    pub struct Job {
        id: u32,
    }

    pub enum Mode {
        Fast,
    }

    pub union Bits {
        raw: u32,
    }

    pub trait Run {
        type Output;
        fn run(&self) -> Self::Output;
    }

    pub type Alias = u32;

    pub const LIMIT: u32 = 3;

    pub static NAME: &str = \"job\";

    impl Job {
        pub const ZERO: u32 = 0;

        pub fn new() -> Self {
            Job { id: 0 }
        }

        pub fn id(&self) -> u32 {
            self.id
        }
    }

    impl Run for Job {
        type Output = u32;

        fn run(&self) -> u32 {
            self.id
        }
    }
}

pub fn entry() {}
";

const RUST_EXPECTED: &[Expected] = &[
    row(StructureKind::Module, Some("inner"), None),
    row(StructureKind::Struct, Some("Job"), Some(0)),
    row(StructureKind::Enum, Some("Mode"), Some(0)),
    row(StructureKind::Union, Some("Bits"), Some(0)),
    row(StructureKind::Trait, Some("Run"), Some(0)),
    row(StructureKind::TypeAlias, Some("Output"), Some(4)),
    row(StructureKind::Method, Some("run"), Some(4)),
    row(StructureKind::TypeAlias, Some("Alias"), Some(0)),
    row(StructureKind::Constant, Some("LIMIT"), Some(0)),
    row(StructureKind::Static, Some("NAME"), Some(0)),
    row(StructureKind::Impl, None, Some(0)),
    row(StructureKind::Constant, Some("ZERO"), Some(10)),
    row(StructureKind::Function, Some("new"), Some(10)),
    row(StructureKind::Method, Some("id"), Some(10)),
    row(StructureKind::Impl, None, Some(0)),
    row(StructureKind::TypeAlias, Some("Output"), Some(14)),
    row(StructureKind::Method, Some("run"), Some(14)),
    row(StructureKind::Function, Some("entry"), None),
];

pub(super) const STRUCTURE_GO_SOURCE: &str = "\
package inventory

type Job struct {
\tID   int
\tname string
}

type Special struct {
\tJob
}

type Runner interface {
\tRun() int
}

type Count int

type Alias = Count

const Limit = 3

var Registry = 0

func New() *Job {
\treturn &Job{}
}

func (j *Job) Run() int {
\treturn j.ID
}
";

const GO_EXPECTED: &[Expected] = &[
    row(StructureKind::Package, Some("inventory"), None),
    row(StructureKind::Struct, Some("Job"), None),
    row(StructureKind::Field, Some("ID"), Some(1)),
    row(StructureKind::Field, Some("name"), Some(1)),
    row(StructureKind::Struct, Some("Special"), None),
    row(StructureKind::Field, Some("Job"), Some(4)),
    row(StructureKind::Interface, Some("Runner"), None),
    row(StructureKind::Method, Some("Run"), Some(6)),
    row(StructureKind::DefinedType, Some("Count"), None),
    row(StructureKind::TypeAlias, Some("Alias"), None),
    row(StructureKind::Constant, Some("Limit"), None),
    row(StructureKind::Variable, Some("Registry"), None),
    row(StructureKind::Function, Some("New"), None),
    row(StructureKind::Method, Some("Run"), None),
];

pub(super) const STRUCTURE_PYTHON_SOURCE: &str = "\
LIMIT = 3


def build():
    return 1


async def fetch():
    return 2


class Job:
    def run(self):
        return 1

    async def start(self):
        return 2

    @staticmethod
    def make():
        return Job()
";

const PYTHON_EXPECTED: &[Expected] = &[
    row(StructureKind::Module, None, None),
    row(StructureKind::Function, Some("build"), Some(0)),
    row(StructureKind::Function, Some("fetch"), Some(0)),
    row(StructureKind::Class, Some("Job"), Some(0)),
    row(StructureKind::Method, Some("run"), Some(3)),
    row(StructureKind::Method, Some("start"), Some(3)),
    row(StructureKind::Method, Some("make"), Some(3)),
];

pub(super) const STRUCTURE_JAVASCRIPT_SOURCE: &str = "\
export function build() {
  return 1;
}

function* counter() {
  yield 1;
}

export class Job {
  limit = 3;

  run() {
    return 1;
  }

  static make() {
    return new Job();
  }
}
";

const JAVASCRIPT_EXPECTED: &[Expected] = &[
    row(StructureKind::Module, None, None),
    row(StructureKind::Function, Some("build"), Some(0)),
    row(StructureKind::Function, Some("counter"), Some(0)),
    row(StructureKind::Class, Some("Job"), Some(0)),
    row(StructureKind::Field, Some("limit"), Some(3)),
    row(StructureKind::Method, Some("run"), Some(3)),
    row(StructureKind::Method, Some("make"), Some(3)),
];

pub(super) const STRUCTURE_TYPESCRIPT_SOURCE: &str = "\
export interface Runner {
  run(): number;
  readonly label: string;
}

export type Alias = number;

export enum Mode {
  Fast,
}

export namespace registry {
  export function build(): number {
    return 1;
  }
}

export abstract class Base {
  protected limit: number = 3;

  abstract run(): number;

  make(): number {
    return 1;
  }
}

function* counter(): Generator<number> {
  yield 1;
}

class Job {
  id = 1;
}
";

const TYPESCRIPT_EXPECTED: &[Expected] = &[
    row(StructureKind::Module, None, None),
    row(StructureKind::Interface, Some("Runner"), Some(0)),
    row(StructureKind::Method, Some("run"), Some(1)),
    row(StructureKind::Field, Some("label"), Some(1)),
    row(StructureKind::TypeAlias, Some("Alias"), Some(0)),
    row(StructureKind::Enum, Some("Mode"), Some(0)),
    row(StructureKind::Module, Some("registry"), Some(0)),
    row(StructureKind::Function, Some("build"), Some(6)),
    row(StructureKind::Class, Some("Base"), Some(0)),
    row(StructureKind::Field, Some("limit"), Some(8)),
    row(StructureKind::Method, Some("run"), Some(8)),
    row(StructureKind::Method, Some("make"), Some(8)),
    row(StructureKind::Function, Some("counter"), Some(0)),
    row(StructureKind::Class, Some("Job"), Some(0)),
    row(StructureKind::Field, Some("id"), Some(13)),
];

pub(super) const STRUCTURE_BASH_SOURCE: &str = "\
greet() {
  echo hi
}

function farewell {
  echo bye
}
";

const BASH_EXPECTED: &[Expected] = &[
    row(StructureKind::Function, Some("greet"), None),
    row(StructureKind::Function, Some("farewell"), None),
];

/// One fixture per grammar the structure contract states a row for.
///
/// TSX shares TypeScript's row and its recognizer, and the dispatch case proves
/// that pairing, so the six rows here are the six the contract closes over.
pub(super) const FIXTURES: &[StructureFixture] = &[
    StructureFixture {
        language: SyntaxLanguage::Rust,
        source: STRUCTURE_RUST_SOURCE,
        expected: RUST_EXPECTED,
        depth: 3,
    },
    StructureFixture {
        language: SyntaxLanguage::Go,
        source: STRUCTURE_GO_SOURCE,
        expected: GO_EXPECTED,
        depth: 9,
    },
    StructureFixture {
        language: SyntaxLanguage::Python,
        source: STRUCTURE_PYTHON_SOURCE,
        expected: PYTHON_EXPECTED,
        depth: 9,
    },
    StructureFixture {
        language: SyntaxLanguage::JavaScript,
        source: STRUCTURE_JAVASCRIPT_SOURCE,
        expected: JAVASCRIPT_EXPECTED,
        depth: 9,
    },
    StructureFixture {
        language: SyntaxLanguage::TypeScript,
        source: STRUCTURE_TYPESCRIPT_SOURCE,
        expected: TYPESCRIPT_EXPECTED,
        depth: 8,
    },
    StructureFixture {
        language: SyntaxLanguage::Bash,
        source: STRUCTURE_BASH_SOURCE,
        expected: BASH_EXPECTED,
        depth: 5,
    },
];
