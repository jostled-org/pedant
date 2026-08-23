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
/// The asymmetric `Join()` and `tx.Join()` calls make file scope observable:
/// neither file may inherit the other file's alias or dot-import binding.
///
/// A third file dot-imports a path no directory of this module holds. A dot
/// import pulls names it does not spell, so a name the corpus cannot answer in
/// that file could still be declared by the package outside it: the answer is
/// "not here" rather than "nowhere", and `outside.go` is the only file here whose
/// unresolved name states it.
///
/// Neither the dot nor the blank form binds a qualifier, so both files write one:
/// `dotted.go` writes `text.Join()` for the package it dot-imports, and
/// `aliased.go` writes `blank.Zero()` for the package it blank-imports. Both
/// packages hold the member the call names, so each qualifier resolves the moment
/// its form binds a name — which neither form may do.
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
    (
        "repo/textutil/text.go",
        "package text\n\nfunc Join() string {\n\treturn \"textutil\"\n}\n",
    ),
    (
        "repo/blank/blank.go",
        "package blank\n\nfunc Zero() string {\n\treturn \"blank\"\n}\n",
    ),
    (
        "repo/aliased.go",
        "package app\n\nimport (\n\t\"x/util\"\n\ttx \"x/text\"\n\t_ \"x/blank\"\n)\n\nfunc Aliased() string {\n\treturn util.Name() + tx.Join() + Join() + blank.Zero()\n}\n",
    ),
    (
        "repo/dotted.go",
        "package app\n\nimport (\n\t. \"x/text\"\n\t\"x/util\"\n)\n\nfunc Dotted() string {\n\treturn Join() + util.Name() + tx.Join() + text.Join()\n}\n",
    ),
    (
        "repo/outside.go",
        "package app\n\nimport . \"example.com/outside\"\n\nfunc Outside() string {\n\treturn Elsewhere()\n}\n",
    ),
    (
        "repo/renamed.go",
        "package app\n\nimport \"x/textutil\"\n\nfunc Renamed() string {\n\treturn text.Join() + textutil.Join()\n}\n",
    ),
];

/// One package whose parameters, receivers, locals, and nested blocks bind the
/// same name an import and a package declaration state.
///
/// A binding that merely suppresses an occurrence proves half the rule. The
/// other half is the claim it blocks, so two locals here shadow a name that
/// would otherwise answer. `Shadowed` binds `util` to `Helper`, which declares
/// its own `Name`, and writes `util.Name()`: the import binds `util` too, and
/// both packages hold a `Name`, so the qualifier decides which package the call
/// enters. `Rebound` binds `Label` over the package's own `Label` and reads it
/// bare, where the package declaration would answer if the binding did not
/// cover it.
pub const SHADOWING: &[FixtureFile] = &[
    MANIFEST,
    (
        "repo/util/util.go",
        "package util\n\nfunc Name() string {\n\treturn \"util\"\n}\n",
    ),
    (
        "repo/shadow.go",
        "package app\n\nimport \"x/util\"\n\nvar Label = \"app\"\n\ntype Counter struct{}\n\nfunc (util Counter) Bump() Counter {\n\treturn util\n}\n\nfunc Nested(util string) string {\n\t{\n\t\tinner := util\n\t\treturn inner\n\t}\n}\n\nfunc Free() string {\n\treturn util.Name()\n}\n\ntype Helper struct{}\n\nfunc (h Helper) Name() string {\n\treturn \"helper\"\n}\n\nfunc Shadowed() string {\n\tutil := Helper{}\n\treturn util.Name()\n}\n\nfunc Rebound() string {\n\tLabel := \"local\"\n\treturn Label\n}\n",
    ),
];

/// Direct, package-qualified, and external calls beside the call shapes that
/// are not static calls: a conversion, a parameter holding a function, a
/// function value held by a local, and two function literals.
///
/// `Indirect` and `Held` state a function value, which is not a closure: neither
/// writes a `func` literal, so a resolver that never walked into one would still
/// answer both. `Literal` and `Captured` write the literal itself, and a literal
/// opens a declaration scope inside a block, which is the one nesting no other
/// shape here produces.
///
/// `Captured` calls a local the enclosing function bound, and its call is the
/// one site here whose answer the literal boundary decides: a resolver whose
/// chain stopped at the literal would see no binding covering `fn`, look the
/// name up as a package name, and state it missing rather than dynamic. Such a
/// resolver withholds the dynamic answer; it cannot invent a static one, because
/// no package declares `fn`. `Literal` calls a package function instead, which a
/// bare lookup answers from the unit's declarations rather than from the chain,
/// so that row states the weaker claim its shape can carry: a reference written
/// inside a literal body is published and resolved at all.
pub const CALL_SHAPES: &[FixtureFile] = &[
    MANIFEST,
    (
        "repo/util/util.go",
        "package util\n\nfunc Name() string {\n\treturn \"util\"\n}\n",
    ),
    (
        "repo/calls.go",
        "package app\n\nimport (\n\t\"fmt\"\n\t\"x/util\"\n)\n\ntype Label string\n\nfunc Local() string {\n\treturn \"local\"\n}\n\nfunc Direct() string {\n\treturn Local()\n}\n\nfunc Qualified() string {\n\treturn util.Name()\n}\n\nfunc External() string {\n\treturn fmt.Sprint(\"external\")\n}\n\nfunc Convert(raw string) Label {\n\treturn Label(raw)\n}\n\nfunc Indirect(fn func() string) string {\n\treturn fn()\n}\n\nfunc Held() string {\n\tfn := Local\n\treturn fn()\n}\n\nfunc Missing() string {\n\treturn DoesNotExist()\n}\n\nfunc MissingQualified() string {\n\treturn util.Nope()\n}\n\nfunc Universe(raw []string) (int, error) {\n\treturn len(append(raw, \"entry\")), nil\n}\n\nfunc Literal() string {\n\tinner := func() string {\n\t\treturn Local()\n\t}\n\treturn inner()\n}\n\nfunc Captured() string {\n\tfn := Local\n\tinner := func() string {\n\t\treturn fn()\n\t}\n\treturn inner()\n}\n",
    ),
    (
        "repo/kinds.go",
        "package app\n\ntype Code int\n\ntype CodeAlias = Code\n\nconst DefaultCode Code = 0\n\nvar CurrentCode Code\n\nfunc ConvertAlias(raw Code) CodeAlias {\n\treturn CodeAlias(raw)\n}\n",
    ),
];

/// Every receiver form a concrete method call is resolved from, plus the
/// embedded promotion, the conditional ambiguity, and the receiver evidence a
/// snapshot cannot complete.
///
/// `Node` declares `Rename` in pointer form and `Label` in value form, and both
/// are called from both receiver forms, because Go selects one method set at a
/// call site: a value receiver reaches a pointer method and a pointer receiver
/// reaches a value method. A fixture that called each method only from the form
/// its declaration wrote would pass under a resolver that matched pointerness.
///
/// `store` declares a second `Node` with a second `Label`, and `foreign.go`
/// declares a receiver of it by writing the package-qualified form. Both packages
/// answer the same method name, so a resolver that dropped the qualifier would
/// publish a resolved call into the wrong package rather than a gap: the crossing
/// row names `x/store#production::Label`, and the bare lookup beside it names
/// `x#production::Label`.
///
/// `Fetch` carries the same crossing one hop further: it *returns* `store.Node`,
/// and `Crossed` binds a receiver from calling it. A declared result names its
/// package through the imports of the file that wrote it, which is not the file
/// asking, so this tier states no receiver type and the call keeps its gap. A
/// resolver that read the result's name without its qualifier would find `app`'s
/// own `Node` and publish a resolved edge into the wrong package.
///
/// The embedding chain is three types deep, and two names answer at two depths
/// each. `Node` declares `Label` and `Base` promotes another, so depth 0 decides;
/// `Base` declares `Ping` and `Root` promotes another, so depth 1 decides over
/// depth 2; `Trace` is declared only on `Root`, so it is reached at depth 2 or
/// not at all. A resolver that flattened the chain would answer two candidates
/// where Go answers one, and one that widened past the first answering level
/// would answer the deeper method.
///
/// `zembed.go` embeds across the crossing and beside a decoy. `ForeignBase`
/// embeds `store.Shared` while the same file declares its own `Shared` with the
/// same `Promote`, so the promoted call answers `x/store#production::Promote`
/// and a resolver that dropped the embedded qualifier — or resolved the
/// embedded name in the embedding package — answers the decoy instead. `Boxed`
/// embeds `*Base`: the star is written outside the embedded type, and promotion
/// runs through the same identity either way.
///
/// `zgaps.go` writes the two embeddings whose written type this tier cannot
/// reach, each beside a decoy the same package declares. `Printed` embeds
/// `fmt.Stringer`, whose package is outside the snapshot, while the file itself
/// declares a `Stringer` with a `String`. `Unbound` writes `store.Shared` where
/// no import binds `store`, which is the file-scope rule the qualified call
/// sites already carry, applied to an embedded type; `zembed.go` declares the
/// `Shared` a resolver dropping that qualifier would find.
///
/// `zshadow.go` writes the third: `Doubled` embeds a bare `Shared` in a file
/// that dot-imports `x/store`, so two packages answer one name. That is a Go
/// program error — no identifier may be declared in both the file and the
/// package block — and it is one the resolver states as a gap rather than
/// deciding, exactly as it does for an ambiguous selector.
///
/// All three promoted calls must state `MissingDefinition`: the corpus holds no
/// such member, which is what the embedding rule says a chain leaving the
/// snapshot leaves behind.
///
/// `zpaths.go` writes the embedding shape depth alone cannot tell apart.
/// `Upper` and `Lower` each embed `Base`, and `Diamond` embeds both, so
/// `d.Ping()` reaches one `Ping` through two embedding paths at one depth. Go
/// counts paths rather than types: the selector is ambiguous and `go build`
/// rejects it. A resolver keying its widened level by the type reached collapses
/// the two paths into one and publishes a resolved call target for a program
/// that does not compile.
///
/// `zowner.go` writes the receiver this tier cannot identify at all: `Orphan`
/// receives an `Unknown` no source declares. The method belongs to a type the
/// corpus does not hold, so the report states no holder for it and the receiver
/// type beside it carries the gap that says why. A resolver falling back to the
/// package makes `Package` a method holder — a containment Go never declares —
/// while the method set beside it records nothing, so the definition invents an
/// owner the method sets disagree with.
pub const METHOD_SETS: &[FixtureFile] = &[
    MANIFEST,
    (
        "repo/store/store.go",
        "package store\n\ntype Node struct{}\n\nfunc (n Node) Label() string {\n\treturn \"store\"\n}\n\ntype Shared struct{}\n\nfunc (s Shared) Promote() string {\n\treturn \"store\"\n}\n",
    ),
    (
        "repo/foreign.go",
        "package app\n\nimport \"x/store\"\n\nfunc Foreign() string {\n\tvar n store.Node\n\treturn n.Label()\n}\n\nfunc Fetch() store.Node {\n\treturn store.Node{}\n}\n\nfunc Crossed() string {\n\tn := Fetch()\n\treturn n.Label()\n}\n",
    ),
    (
        "repo/types.go",
        "package app\n\ntype Root struct{}\n\nfunc (r Root) Trace() string {\n\treturn \"root\"\n}\n\nfunc (r Root) Ping() string {\n\treturn \"root\"\n}\n\ntype Base struct {\n\tRoot\n}\n\nfunc (b Base) Ping() string {\n\treturn \"ping\"\n}\n\nfunc (b Base) Label() string {\n\treturn \"base\"\n}\n\ntype Node struct {\n\tBase\n\tName string\n}\n\nfunc (n *Node) Rename(next string) {\n\tn.Name = next\n}\n\nfunc (n Node) Label() string {\n\treturn n.Name\n}\n\nfunc NewNode() *Node {\n\treturn &Node{}\n}\n",
    ),
    (
        "repo/receivers.go",
        "package app\n\nfunc Literal() string {\n\tn := Node{}\n\treturn n.Label()\n}\n\nfunc Address() string {\n\tn := &Node{}\n\treturn n.Ping()\n}\n\nfunc Result() string {\n\tn := NewNode()\n\treturn n.Label()\n}\n\nfunc Converted(raw Node) string {\n\tn := Node(raw)\n\treturn n.Label()\n}\n\nfunc Declared() string {\n\tvar n Node\n\treturn n.Label()\n}\n\nfunc Indexed(all []Node) string {\n\treturn all[0].Label()\n}\n\nfunc Renamed() string {\n\tn := Node{}\n\tn.Rename(\"next\")\n\treturn n.Label()\n}\n\nfunc Pointed() string {\n\tn := NewNode()\n\tn.Rename(\"next\")\n\treturn n.Label()\n}\n\nfunc Dereferenced() string {\n\tn := NewNode()\n\treturn (*n).Label()\n}\n\nfunc Addressed() string {\n\tn := Node{}\n\treturn (&n).Ping()\n}\n\nfunc Promoted() string {\n\tn := Node{}\n\treturn n.Trace()\n}\n\nfunc MissingMember() string {\n\tvar n Node\n\treturn n.Absent()\n}\n",
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
    (
        "repo/zembed.go",
        "package app\n\nimport \"x/store\"\n\ntype Shared struct{}\n\nfunc (s Shared) Promote() string {\n\treturn \"local\"\n}\n\ntype ForeignBase struct {\n\tstore.Shared\n}\n\nfunc Embedded() string {\n\tvar n ForeignBase\n\treturn n.Promote()\n}\n\ntype Boxed struct {\n\t*Base\n}\n\nfunc Boxing() string {\n\tvar b Boxed\n\treturn b.Ping()\n}\n",
    ),
    (
        "repo/zgaps.go",
        "package app\n\nimport \"fmt\"\n\ntype Stringer struct{}\n\nfunc (s Stringer) String() string {\n\treturn \"local\"\n}\n\ntype Printed struct {\n\tfmt.Stringer\n}\n\ntype Unbound struct {\n\tstore.Shared\n}\n\nfunc Outside() string {\n\tvar p Printed\n\treturn p.String()\n}\n\nfunc Unimported() string {\n\tvar u Unbound\n\treturn u.Promote()\n}\n",
    ),
    (
        "repo/zshadow.go",
        "package app\n\nimport . \"x/store\"\n\ntype Doubled struct {\n\tShared\n}\n\nfunc Twinned() string {\n\tvar d Doubled\n\treturn d.Promote()\n}\n",
    ),
    (
        "repo/zowner.go",
        "package app\n\nfunc (u Unknown) Orphan() string {\n\treturn \"orphan\"\n}\n",
    ),
    (
        "repo/zpaths.go",
        "package app\n\ntype Upper struct {\n\tBase\n}\n\ntype Lower struct {\n\tBase\n}\n\ntype Diamond struct {\n\tUpper\n\tLower\n}\n\nfunc Ambiguous() string {\n\tvar d Diamond\n\treturn d.Ping()\n}\n",
    ),
];

/// One directory stating all three compilation contexts beside a second
/// package, which is what a wrapper binds one report unit per.
///
/// `tuned` is declared in a platform-suffixed source, so the only build that
/// holds it is one this tier does not evaluate. It sits here rather than in a
/// fixture of its own because a wrapper states certainty over the same report it
/// binds: a conditioned answer proved beside an unconditioned one is what shows
/// the rule discriminates.
pub const BOUND_CONTEXTS: &[FixtureFile] = &[
    MANIFEST,
    (
        "repo/app.go",
        "package app\n\nimport \"x/util\"\n\nfunc Run() string {\n\treturn util.Name() + tuned()\n}\n",
    ),
    (
        "repo/tuned_linux.go",
        "package app\n\nfunc tuned() string {\n\treturn \"linux\"\n}\n",
    ),
    (
        "repo/app_test.go",
        "package app\n\nfunc probe() string {\n\treturn Run()\n}\n",
    ),
    (
        "repo/api_test.go",
        "package app_test\n\nimport \"x\"\n\nfunc drive() string {\n\treturn app.Run()\n}\n",
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
