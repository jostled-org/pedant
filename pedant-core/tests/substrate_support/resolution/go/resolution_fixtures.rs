//! Go module repositories the resolver cases read.
//!
//! Every tree is a real module with real sources, because the subject is what a
//! snapshot of real Go states: a fixture that stated only the shape a case
//! wanted would prove the case rather than the resolver.

use crate::resolution::fixture::FixtureFile;

/// The manifest every fixture here shares: one main module named `x`, so an
/// import path is the directory beneath it.
const MANIFEST: FixtureFile = ("repo/go.mod", "module x\n\ngo 1.22\n");

/// Two files of one package importing the same two packages four ways: a
/// default name, an explicit alias, a dot import, and a blank import.
///
/// `util` is imported by both files, which is what makes file scope observable:
/// a binding shared by two files is still two bindings.
pub const IMPORT_FORMS: &[FixtureFile] = &[
    MANIFEST,
    (
        "repo/util/util.go",
        "package util\n\nfunc Name() string {\n\treturn \"util\"\n}\n",
    ),
    (
        "repo/text/text.go",
        "package text\n\nfunc Join() string {\n\treturn \"text\"\n}\n",
    ),
    ("repo/blank/blank.go", "package blank\n"),
    (
        "repo/aliased.go",
        "package app\n\nimport (\n\t\"x/util\"\n\ttx \"x/text\"\n\t_ \"x/blank\"\n)\n\nfunc Aliased() string {\n\treturn util.Name() + tx.Join()\n}\n",
    ),
    (
        "repo/dotted.go",
        "package app\n\nimport (\n\t. \"x/text\"\n\t\"x/util\"\n)\n\nfunc Dotted() string {\n\treturn Join() + util.Name()\n}\n",
    ),
];

/// One package whose parameters, receivers, locals, and nested blocks bind the
/// same name an import and a package declaration state.
pub const SHADOWING: &[FixtureFile] = &[
    MANIFEST,
    (
        "repo/util/util.go",
        "package util\n\nfunc Name() string {\n\treturn \"util\"\n}\n",
    ),
    (
        "repo/shadow.go",
        "package app\n\nimport \"x/util\"\n\ntype Counter struct{}\n\nfunc (util Counter) Bump() Counter {\n\treturn util\n}\n\nfunc Nested(util string) string {\n\t{\n\t\tinner := util\n\t\treturn inner\n\t}\n}\n\nfunc Free() string {\n\treturn util.Name()\n}\n",
    ),
];

/// Direct, package-qualified, and external calls beside the three call shapes
/// that are not static calls: a conversion, a parameter holding a function, and
/// a closure held by a local.
pub const CALL_SHAPES: &[FixtureFile] = &[
    MANIFEST,
    (
        "repo/util/util.go",
        "package util\n\nfunc Name() string {\n\treturn \"util\"\n}\n",
    ),
    (
        "repo/calls.go",
        "package app\n\nimport (\n\t\"fmt\"\n\t\"x/util\"\n)\n\ntype Label string\n\nfunc Local() string {\n\treturn \"local\"\n}\n\nfunc Direct() string {\n\treturn Local()\n}\n\nfunc Qualified() string {\n\treturn util.Name()\n}\n\nfunc External() string {\n\treturn fmt.Sprint(\"external\")\n}\n\nfunc Convert(raw string) Label {\n\treturn Label(raw)\n}\n\nfunc Indirect(fn func() string) string {\n\treturn fn()\n}\n\nfunc Closure() string {\n\tfn := Local\n\treturn fn()\n}\n",
    ),
];

/// Every receiver form a concrete method call is resolved from, plus the
/// embedded promotion, the conditional ambiguity, and the receiver evidence a
/// snapshot cannot complete.
pub const METHOD_SETS: &[FixtureFile] = &[
    MANIFEST,
    (
        "repo/types.go",
        "package app\n\ntype Base struct{}\n\nfunc (b Base) Ping() string {\n\treturn \"ping\"\n}\n\ntype Node struct {\n\tBase\n\tName string\n}\n\nfunc (n *Node) Rename(next string) {\n\tn.Name = next\n}\n\nfunc (n Node) Label() string {\n\treturn n.Name\n}\n\nfunc NewNode() *Node {\n\treturn &Node{}\n}\n",
    ),
    (
        "repo/receivers.go",
        "package app\n\nfunc Literal() string {\n\tn := Node{}\n\treturn n.Label()\n}\n\nfunc Address() string {\n\tn := &Node{}\n\treturn n.Ping()\n}\n\nfunc Result() string {\n\tn := NewNode()\n\treturn n.Label()\n}\n\nfunc Converted(raw Node) string {\n\tn := Node(raw)\n\treturn n.Label()\n}\n\nfunc Declared() string {\n\tvar n Node\n\treturn n.Label()\n}\n\nfunc Indexed(all []Node) string {\n\treturn all[0].Label()\n}\n",
    ),
    (
        "repo/plat_linux.go",
        "package app\n\nfunc (n *Node) Platform() string {\n\treturn \"linux\"\n}\n",
    ),
    (
        "repo/plat_windows.go",
        "package app\n\nfunc (n *Node) Platform() string {\n\treturn \"windows\"\n}\n",
    ),
    (
        "repo/platform.go",
        "package app\n\nfunc Platform() string {\n\tn := NewNode()\n\treturn n.Platform()\n}\n",
    ),
];

/// One directory stating all three compilation contexts beside a second
/// package, which is what a wrapper binds one report unit per.
pub const BOUND_CONTEXTS: &[FixtureFile] = &[
    MANIFEST,
    (
        "repo/app.go",
        "package app\n\nimport \"x/util\"\n\nfunc Run() string {\n\treturn util.Name()\n}\n",
    ),
    (
        "repo/app_test.go",
        "package app\n\nfunc probe() string {\n\treturn Run()\n}\n",
    ),
    (
        "repo/api_test.go",
        "package app_test\n\nimport \"x\"\n\nfunc drive() string {\n\treturn x.Run()\n}\n",
    ),
    (
        "repo/util/util.go",
        "package util\n\nfunc Name() string {\n\treturn \"util\"\n}\n",
    ),
];

/// One local package import and nothing else that carries a candidate.
///
/// A package reference always names exactly one package, so its ceiling is
/// proved at zero rather than by a duplicate: two directories cannot share an
/// import path, so a two-candidate package reference does not exist.
pub const LIMIT_PACKAGE: &[FixtureFile] = &[
    MANIFEST,
    ("repo/util/util.go", "package util\n"),
    ("repo/a.go", "package app\n\nimport \"x/util\"\n"),
];

/// One direct call whose target is declared twice, once per platform.
pub const LIMIT_FUNCTION: &[FixtureFile] = &[
    MANIFEST,
    ("repo/a.go", "package app\n\nfunc A() {\n\tB()\n}\n"),
    ("repo/b_linux.go", "package app\n\nfunc B() {}\n"),
    ("repo/b_windows.go", "package app\n\nfunc B() {}\n"),
];

/// One package-level value read whose declaration is stated twice.
pub const LIMIT_VALUE: &[FixtureFile] = &[
    MANIFEST,
    (
        "repo/a.go",
        "package app\n\nfunc A() int {\n\treturn Count\n}\n",
    ),
    ("repo/c_linux.go", "package app\n\nvar Count int\n"),
    ("repo/c_windows.go", "package app\n\nvar Count int\n"),
];

/// One concrete method call whose method is declared twice.
pub const LIMIT_METHOD: &[FixtureFile] = &[
    MANIFEST,
    (
        "repo/a.go",
        "package app\n\ntype T struct{}\n\nfunc A() {\n\tvar t T\n\tt.M()\n}\n",
    ),
    ("repo/m_linux.go", "package app\n\nfunc (t T) M() {}\n"),
    ("repo/m_windows.go", "package app\n\nfunc (t T) M() {}\n"),
];
