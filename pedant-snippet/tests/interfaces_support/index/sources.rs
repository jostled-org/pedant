//! The corpus every index and navigation claim is taken over.
//!
//! One catalog: the six language sources, the manifests that select projects
//! over them, the small paired repositories a single-claim row needs, and the
//! mixed repository that holds all of it. [`fixture`](super::fixture) writes
//! these rows to a temporary tree; nothing here touches a filesystem.
//!
//! Apart from that module because the two are different concerns. A row added
//! to this catalog changes what every claim is made about; a change to the
//! writer changes how the tree is laid down and nothing about its contents.

/// The Rust library source, stating every structure the Rust row of the
/// contract names.
///
/// `make` is what `crate-a/src/main.rs` calls, which is what puts this one
/// physical file in both of the member's target slices.
pub const RUST_LIBRARY: &str = "\
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

pub fn make() -> u32 {
    0
}
";

/// The Go main-module source, stating every structure the Go row names.
pub const GO_MAIN: &str = "\
package main

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

/// The Python source, stating every structure the Python row names.
pub const PYTHON_TOOL: &str = "\
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

/// The JavaScript source, stating every structure the JavaScript row names.
pub const JAVASCRIPT_APP: &str = "\
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

/// The TypeScript source, stating every structure the TypeScript row names.
pub const TYPESCRIPT_APP: &str = "\
export interface Runner {
  run(): number;
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

/// The Bash source, stating every structure the Bash row names.
pub const BASH_TOOL: &str = "\
greet() {
  echo hi
}

function farewell {
  echo bye
}
";

/// The manifest of the one Cargo package every Rust fixture here states.
pub const CRATE_A_MANIFEST: &str =
    "[package]\nname = \"crate-a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n";

/// One Cargo package whose library resolves, without a workspace above it.
///
/// The smallest repository that states a Rust project authority, which is what
/// every row about one project's own record is taken over.
pub const RUST_PACKAGE: &[(&str, &str)] = &[
    ("Cargo.toml", CRATE_A_MANIFEST),
    ("src/lib.rs", "pub fn make() -> u32 {\n    1\n}\n"),
];

/// A Go main module: its manifest and its one source.
const GO_MAIN_ROWS: [(&str, &str); 2] = [
    ("go.mod", "module example.com/main\n\ngo 1.22\n"),
    ("main.go", "package main\n\nfunc Start() {}\n"),
];

/// A Go main module alone, stating one authority and one source.
pub const GO_MAIN_MODULE: &[(&str, &str)] = &GO_MAIN_ROWS;

/// An independent Go module nested beneath another module's root.
const GO_NESTED_ROWS: [(&str, &str); 2] = [
    ("nested/go.mod", "module example.com/nested\n\ngo 1.22\n"),
    ("nested/lib.go", "package nested\n\nfunc Helper() {}\n"),
];

/// A Go main module and an independent module nested beneath its root.
///
/// Two authorities, so a row that must tell one project's own answer from the
/// whole index's has a second project to tell it against.
pub const GO_MODULES: &[(&str, &str)] = &[
    GO_MAIN_ROWS[0],
    GO_MAIN_ROWS[1],
    GO_NESTED_ROWS[0],
    GO_NESTED_ROWS[1],
];

/// One clean Python source every paired fixture admits.
pub const KEPT: (&str, &str) = ("a.py", "def a():\n    return 1\n");

/// The same file [`KEPT`] names, holding different bytes.
///
/// The one row a claim about the exact source digest is made over: the path is
/// the path the index already holds, so nothing but the bytes moved.
pub const EDITED: (&str, &str) = ("a.py", "def a():\n    return 2\n");

/// A second clean Python source, sorting after [`KEPT`].
///
/// The pair is what every order-independence and first-excess row needs: two
/// sources one ceiling can tell apart, whichever order the tree was written in.
pub const SECOND: (&str, &str) = ("b.py", "def b():\n    return 2\n");

/// The one source a confinement repository holds beneath its own root.
pub const KEPT_ONLY: (&str, &str) = ("kept.py", "def kept():\n    return 1\n");

/// The one source a confinement repository holds outside the root under test.
///
/// What a link that leaves the root points at, so a row that admitted it would
/// be admitting a file the index was never given.
pub const OUTSIDE: (&str, &str) = ("secret.py", "def secret():\n    return 1\n");

/// A Python source no inventory accepts, which is recorded and not admitted.
pub const BROKEN_SOURCE: &str = "def broken(:\n    return\n";

/// Bytes that decode as no text, so nothing ever reaches a parser.
pub const UNDECODABLE: &[u8] = &[0xff, 0xfe, 0x00, b'x'];

/// The mixed six-language repository every corpus claim is made against.
///
/// It states, deliberately: a Cargo workspace whose member is reached through
/// the root manifest; a library both that member's targets reach, so one
/// physical source belongs to two slices; a Go main module and an independent
/// nested module; one source in each of the four syntax-only languages; a
/// `tsconfig.json` and a `jsconfig.json`, which are not project authorities in
/// this design; an ignore file and the file it excludes; and two hard-excluded
/// directories.
///
/// Each of the six language sources states the whole of its row of the closed
/// structure table, because the navigation cases read this repository and an
/// outline claim is only as complete as the source it is taken over.
pub const MIXED_REPOSITORY: &[(&str, &str)] = &[
    (
        "Cargo.toml",
        "[workspace]\nmembers = [\"crate-a\"]\nresolver = \"3\"\n",
    ),
    ("crate-a/Cargo.toml", CRATE_A_MANIFEST),
    ("crate-a/src/lib.rs", RUST_LIBRARY),
    (
        "crate-a/src/main.rs",
        "fn main() {\n    let _ = crate_a::make();\n}\n",
    ),
    GO_MAIN_ROWS[0],
    ("main.go", GO_MAIN),
    GO_NESTED_ROWS[0],
    GO_NESTED_ROWS[1],
    ("web/app.js", JAVASCRIPT_APP),
    ("web/app.ts", TYPESCRIPT_APP),
    ("web/tsconfig.json", "{}\n"),
    ("web/jsconfig.json", "{}\n"),
    ("scripts/tool.py", PYTHON_TOOL),
    ("scripts/tool.sh", BASH_TOOL),
    (".gitignore", "excluded/\n"),
    ("excluded/hidden.py", "def hidden():\n    return 2\n"),
    (
        "node_modules/pkg/index.js",
        "export function vendored() {}\n",
    ),
    ("target/debug/generated.rs", "pub fn generated() {}\n"),
];

/// Every source path the mixed repository admits, sorted.
pub const MIXED_SOURCES: &[&str] = &[
    "crate-a/src/lib.rs",
    "crate-a/src/main.rs",
    "main.go",
    "nested/lib.go",
    "scripts/tool.py",
    "scripts/tool.sh",
    "web/app.js",
    "web/app.ts",
];
