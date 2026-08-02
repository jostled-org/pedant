//! Per-language fixtures for the `enclosing_unit` root.
//!
//! One source per language serves both its backend's declaration table and the
//! cross-cutting location, absence, and purity rules, so a backend has exactly
//! one place to describe itself.
//!
//! [`Row`] lives here rather than with the table driver because it is the shape
//! every written-down declaration takes: a fixture's target, a minimal
//! declaration's target, and every row of a backend's table are the same
//! statement. The driver in `table.rs` consumes them.

use pedant_syntax::{LineSpan, SourceUnitKind, SyntaxLanguage};

/// One recognized-declaration row: the declaration holding `needle`.
///
/// Every field is a written-down statement. Nothing here is computed from the
/// source, so a row can name a declaration that opens after its line's
/// indentation or closes before its line's last byte, and a backend that
/// returns the wrong extent fails rather than matching a rebuilt expectation.
#[derive(Clone, Copy)]
pub struct Row {
    /// A unique substring inside the expected declaration.
    pub needle: &'static str,
    /// The kind that declaration reports.
    pub kind: SourceUnitKind,
    /// The name that declaration reports.
    pub name: Option<&'static str>,
    /// Its one-based inclusive first and last line.
    pub span: LineSpan,
    /// The byte-exact text it returns.
    pub text: &'static str,
}

/// One language's source and the declaration the cross-cutting rules resolve
/// against.
///
/// The target is a [`Row`], and each backend's table names that same constant
/// as one of its elements, so a fixture's declaration is written down once and
/// the table driver and the cross-cutting rules cannot disagree about it.
///
/// Every source holds exactly one `é`. It sits inside the target declaration
/// with more text after it on its line, so the location rules can probe the
/// byte offset at, inside, and after one multi-byte code point.
///
/// Gated with everything that reads a fixture: a build linking no extraction
/// backend has no fixture to describe.
#[cfg(any(feature = "rust", feature = "_ts"))]
pub struct Fixture {
    /// The syntax language the source is written in.
    pub language: SyntaxLanguage,
    /// The source every case for this language reads.
    pub source: &'static str,
    /// A unique substring on a line outside every recognized declaration.
    pub outside: &'static str,
    /// The declaration the cross-cutting rules resolve, stated once.
    pub target: Row,
}

#[cfg(feature = "rust")]
pub const RUST_SOURCE: &str = r#"use std::fmt;

pub struct Config {
    pub retries: usize,
}

pub enum Mode {
    Fast,
    Slow,
}

pub union Word {
    bits: u32,
    bytes: [u8; 4],
}

pub trait Runner {
    fn describe(&self) -> usize {
        11
    }
}

pub type Handle = usize;

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn tag() -> usize {
            7
        }
        f.write_str("héllo")
    }
}

impl Runner for Mode {}

pub fn build(retries: usize) -> Config {
    Config { retries }
}
"#;

#[cfg(feature = "rust")]
pub const RUST: Fixture = Fixture {
    language: SyntaxLanguage::Rust,
    source: RUST_SOURCE,
    outside: "use std::fmt;",
    target: Row {
        needle: "f.write_str",
        kind: SourceUnitKind::Method,
        name: Some("fmt"),
        span: LineSpan { start: 26, end: 31 },
        text: "fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {\n        fn tag() -> usize {\n            7\n        }\n        f.write_str(\"héllo\")\n    }",
    },
};

#[cfg(feature = "ts-python")]
pub const PYTHON_SOURCE: &str = r#"import os


@dataclass
class Service:
    """Route table."""

    @staticmethod
    def build(count):
        def scale(step):
            return step * 2
        return scale(count) + 1

    def run(self):
        label = "héllo"
        return label


def helper(value):
    return value


class Registry:
    entries = []


@cache
def resolve(key):
    return key
"#;

#[cfg(feature = "ts-python")]
pub const PYTHON: Fixture = Fixture {
    language: SyntaxLanguage::Python,
    source: PYTHON_SOURCE,
    outside: "import os",
    target: Row {
        needle: "return label",
        kind: SourceUnitKind::Method,
        name: Some("run"),
        span: LineSpan { start: 14, end: 16 },
        text: "def run(self):\n        label = \"héllo\"\n        return label",
    },
};

#[cfg(feature = "ts-javascript")]
pub const JAVASCRIPT_SOURCE: &str = r#"const registry = new Map();

function build(count) {
  return count + 1;
}

function* stream(limit) {
  yield limit;
}

class Service {
  run(label) {
    const greeting = `héllo ${label}`;
    return greeting;
  }
}
"#;

#[cfg(feature = "ts-javascript")]
pub const JAVASCRIPT: Fixture = Fixture {
    language: SyntaxLanguage::JavaScript,
    source: JAVASCRIPT_SOURCE,
    outside: "const registry",
    target: Row {
        needle: "return greeting;",
        kind: SourceUnitKind::Method,
        name: Some("run"),
        span: LineSpan { start: 12, end: 15 },
        text: "run(label) {\n    const greeting = `héllo ${label}`;\n    return greeting;\n  }",
    },
};

#[cfg(feature = "ts-typescript")]
pub const TYPESCRIPT_SOURCE: &str = r#"const VERSION = 1;

function build(count: number): number {
  return count + 1;
}

function* stream(limit: number) {
  yield limit;
}

abstract class Service {
  abstract name(): string;

  run(label: string): string {
    const greeting = `héllo ${label}`;
    return greeting;
  }
}

class Plain {
  ping(): number {
    return 1;
  }
}
"#;

#[cfg(feature = "ts-typescript")]
pub const TYPESCRIPT: Fixture = Fixture {
    language: SyntaxLanguage::TypeScript,
    source: TYPESCRIPT_SOURCE,
    outside: "const VERSION",
    target: Row {
        needle: "return greeting;",
        kind: SourceUnitKind::Method,
        name: Some("run"),
        span: LineSpan { start: 14, end: 17 },
        text: "run(label: string): string {\n    const greeting = `héllo ${label}`;\n    return greeting;\n  }",
    },
};

#[cfg(feature = "ts-typescript")]
pub const TSX_SOURCE: &str = r#"const theme = "dark";

function Badge(label: string) {
  return <span className="badge">{label}</span>;
}

function* frames(limit: number) {
  yield <hr key={limit} />;
}

abstract class Panel {
  abstract title(): string;

  render(label: string) {
    const greeting = `héllo ${label}`;
    return <div title={greeting} />;
  }
}

class Plain {
  icon() {
    return <i />;
  }
}
"#;

#[cfg(feature = "ts-typescript")]
pub const TSX: Fixture = Fixture {
    language: SyntaxLanguage::Tsx,
    source: TSX_SOURCE,
    outside: "const theme",
    target: Row {
        needle: "return <div",
        kind: SourceUnitKind::Method,
        name: Some("render"),
        span: LineSpan { start: 14, end: 17 },
        text: "render(label: string) {\n    const greeting = `héllo ${label}`;\n    return <div title={greeting} />;\n  }",
    },
};

/// The Go source, whose trailing `type Alias = int` is the alias half of the
/// rule `go_struct` states: a type specification is a unit only when it
/// declares a struct. It sits after the grouped block so the group's own line
/// numbers do not depend on it.
#[cfg(feature = "ts-go")]
pub const GO_SOURCE: &str = r#"package main

import "fmt"

type Config struct {
    Retries int
}

type Handler interface {
    Run() int
}

func build(count int) int {
    return count + 1
}

func (c Config) Run() int {
    label := "héllo"
    fmt.Println(label)
    return c.Retries
}

type (
    Group struct {
        Name string
    }

    Marker interface {
        Mark()
    }
)

type Alias = int
"#;

#[cfg(feature = "ts-go")]
pub const GO: Fixture = Fixture {
    language: SyntaxLanguage::Go,
    source: GO_SOURCE,
    outside: "package main",
    target: Row {
        needle: "return c.Retries",
        kind: SourceUnitKind::Method,
        name: Some("Run"),
        span: LineSpan { start: 17, end: 21 },
        text: "func (c Config) Run() int {\n    label := \"héllo\"\n    fmt.Println(label)\n    return c.Retries\n}",
    },
};

#[cfg(feature = "ts-bash")]
pub const BASH_SOURCE: &str = r#"set -euo pipefail

build() {
  local count="$1"
  echo "$((count + 1))"
}

function run() {
  local label="héllo"
  echo "$label"
}
"#;

#[cfg(feature = "ts-bash")]
pub const BASH: Fixture = Fixture {
    language: SyntaxLanguage::Bash,
    source: BASH_SOURCE,
    outside: "set -euo pipefail",
    target: Row {
        needle: "echo \"$label\"",
        kind: SourceUnitKind::Function,
        name: Some("run"),
        span: LineSpan { start: 8, end: 11 },
        text: "function run() {\n  local label=\"héllo\"\n  echo \"$label\"\n}",
    },
};

/// Every fixture whose extraction backend this build enables.
///
/// A compile-time slice, because every fixture is a `const` of static text and
/// `Copy` enums. The cfg on each element is the same gate its constant carries,
/// so a build links exactly the fixtures it links backends for.
#[cfg(any(feature = "rust", feature = "_ts"))]
pub const ENABLED: &[Fixture] = &[
    #[cfg(feature = "rust")]
    RUST,
    #[cfg(feature = "ts-python")]
    PYTHON,
    #[cfg(feature = "ts-javascript")]
    JAVASCRIPT,
    #[cfg(feature = "ts-typescript")]
    TYPESCRIPT,
    #[cfg(feature = "ts-typescript")]
    TSX,
    #[cfg(feature = "ts-go")]
    GO,
    #[cfg(feature = "ts-bash")]
    BASH,
];

/// Declare one enum's variant array and its exhaustive spelling table from a
/// single list.
///
/// A hand-written fixed-size array of listed variants keeps compiling when the
/// model gains a variant: only an exhaustive match breaks, and the array
/// silently stays one short. Generating both from one list closes that. The
/// match fails to compile until the new variant is listed, listing it grows the
/// array, and a duplicated or transposed entry fails as an unreachable arm.
macro_rules! declare_variants {
    ($enum:ident, $array:ident, $spelling:ident, $($variant:ident => $name:literal),+ $(,)?) => {
        /// Every variant this list names, in declaration order.
        ///
        /// Generated beside the spelling table below, so the two cannot
        /// disagree about which variants the model declares.
        pub const $array: [$enum; [$(stringify!($variant)),+].len()] = [$($enum::$variant),+];

        /// The snake_case serialized spelling of one variant.
        ///
        /// An exhaustive match, so a new variant fails to compile until its
        /// spelling is stated in the list above.
        pub fn $spelling(value: $enum) -> &'static str {
            match value {
                $($enum::$variant => $name),+
            }
        }
    };
}

declare_variants!(
    SyntaxLanguage,
    ALL_LANGUAGES,
    language_name,
    Rust => "rust",
    Python => "python",
    JavaScript => "java_script",
    TypeScript => "type_script",
    Tsx => "tsx",
    Go => "go",
    Bash => "bash",
);

declare_variants!(
    SourceUnitKind,
    ALL_KINDS,
    kind_name,
    Function => "function",
    Method => "method",
    Struct => "struct",
    Enum => "enum",
    Union => "union",
    Trait => "trait",
    TypeAlias => "type_alias",
    Impl => "impl",
    Class => "class",
);
