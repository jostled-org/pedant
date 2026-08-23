//! Go module repositories the structural-interface cases read.
//!
//! Every interface here is written beside the concrete types that answer it and
//! the ones that nearly do. A corpus holding only implementors would pass under
//! a resolver that never compared a signature, so each fixture states its own
//! falsification: a type answering the right names with the wrong types, a type
//! answering in the wrong package, and a type answering one method short.

use crate::resolution::fixture::FixtureFile;

/// The manifest every fixture here shares: one main module named `x`, so an
/// import path is the directory beneath it.
const MANIFEST: FixtureFile = ("repo/go.mod", "module x\n\ngo 1.22\n");

/// Two packages whose interfaces and concrete types cross: value receivers,
/// a pointer receiver, promotion through an embedded type, an embedded
/// interface, and two near misses.
///
/// `Person` answers every interface `shape` declares, and `Embedder` answers
/// them only through the type it embeds, so the promoted method set is what
/// carries its rows. `Counter` answers `Speaker` with a pointer receiver, which
/// keeps the method out of the value form's method set: its row must name
/// `*Counter`, because a value of `Counter` does not implement `Speaker` at all.
///
/// `Mismatch` and `Local` are the falsifications. `Mismatch` writes `Speak`
/// with a `string` parameter where `Speaker` requires an `int`, so a comparison
/// reading only method names states a relation Go does not hold. `Local` writes
/// `Tag` over its own package's `Token` where `shape.Tagger` requires
/// `shape.Token`, so a comparison reading a type's name without its package
/// states the same false relation one level deeper — and `Person.Tag` beside it
/// writes the qualified form of the very type `Tagger` names bare, which a
/// comparison that failed to canonicalize either spelling would refuse.
///
/// `plat_linux.go` declares one more implementor under a build predicate this
/// tier does not evaluate, so the relation it states is possible rather than
/// proved while every other relation here is proved.
pub const INTERFACES: &[FixtureFile] = &[
    MANIFEST,
    (
        "repo/shape/shape.go",
        "package shape\n\ntype Token struct{}\n\ntype Speaker interface {\n\tSpeak(volume int) string\n}\n\ntype Named interface {\n\tName() string\n}\n\ntype Loud interface {\n\tSpeaker\n\tShout() string\n}\n\ntype Tagger interface {\n\tTag(t Token) string\n}\n",
    ),
    (
        "repo/impl.go",
        "package app\n\nimport \"x/shape\"\n\ntype Token struct{}\n\ntype Person struct{}\n\nfunc (p Person) Speak(volume int) string {\n\treturn \"person\"\n}\n\nfunc (p Person) Name() string {\n\treturn \"person\"\n}\n\nfunc (p Person) Shout() string {\n\treturn \"PERSON\"\n}\n\nfunc (p Person) Tag(t shape.Token) string {\n\treturn \"tag\"\n}\n\ntype Counter struct{}\n\nfunc (c *Counter) Speak(volume int) string {\n\treturn \"counter\"\n}\n\ntype Embedder struct {\n\tPerson\n}\n\ntype Mute struct{}\n\nfunc (m Mute) Name() string {\n\treturn \"mute\"\n}\n\ntype Mismatch struct{}\n\nfunc (m Mismatch) Speak(volume string) string {\n\treturn \"mismatch\"\n}\n\ntype Local struct{}\n\nfunc (l Local) Tag(t Token) string {\n\treturn \"local\"\n}\n",
    ),
    (
        "repo/plat_linux.go",
        "package app\n\ntype Tuned struct{}\n\nfunc (t Tuned) Name() string {\n\treturn \"linux\"\n}\n",
    ),
];

/// One package whose three interfaces have several implementors, exactly one,
/// and none at all, each dispatched through an interface-typed parameter.
///
/// The three arities are the whole subject: a dispatch through `Solo` names one
/// concrete method and must still stay possible, because the value behind the
/// interface is chosen at run time whatever the corpus happens to hold.
pub const DISPATCH: &[FixtureFile] = &[
    MANIFEST,
    (
        "repo/dispatch.go",
        "package app\n\ntype Greeter interface {\n\tGreet() string\n}\n\ntype Silent interface {\n\tHush() string\n}\n\ntype Solo interface {\n\tOnly() string\n}\n\ntype One struct{}\n\nfunc (o One) Greet() string {\n\treturn \"one\"\n}\n\ntype Two struct{}\n\nfunc (t Two) Greet() string {\n\treturn \"two\"\n}\n\ntype Alone struct{}\n\nfunc (a Alone) Only() string {\n\treturn \"alone\"\n}\n\nfunc Call(g Greeter) string {\n\treturn g.Greet()\n}\n\nfunc Quiet(s Silent) string {\n\treturn s.Hush()\n}\n\nfunc Single(s Solo) string {\n\treturn s.Only()\n}\n",
    ),
];

/// Every way an interface comparison is left incomplete, each beside a type
/// that answers every method the corpus can name.
///
/// `Printer` embeds an interface from a package outside the snapshot, `Scaled`
/// states a type set rather than methods alone, `Writer` requires a method
/// whose parameter names no single type, and `Both` answers `Ping` twice at one
/// embedding depth. `Left` and `Right` are the control: each answers `Pinger`
/// from complete evidence, so a resolver that reported every relation as
/// incomplete fails against them.
///
/// `Diamond` states the ambiguity `Both` cannot. Go's promotion rule counts
/// paths rather than types: `Upper` and `Lower` each embed the same `Left`, so
/// `Diamond` reaches one `Ping` twice at one depth and the selector is illegal
/// exactly as `Both`'s is. A resolver keying its widened level by the type
/// reached collapses the two paths into one and states a proved relation for a
/// program `go build` refuses. `Upper` and `Lower` beside it are the control:
/// each reaches the same `Ping` once, and each proves the relation.
///
/// `Carrier` embeds the interface itself, which Go admits: a struct embedding
/// `Pinger` promotes `Pinger`'s own method into its method set and implements
/// `Pinger`. The answering member is an interface method rather than a
/// receiver's, and a comparison admitting only the second states nothing at all
/// about `Carrier` — neither proved, nor possible, nor a gap.
pub const INTERFACE_GAPS: &[FixtureFile] = &[
    MANIFEST,
    (
        "repo/gaps.go",
        "package app\n\nimport \"fmt\"\n\ntype Printer interface {\n\tfmt.Stringer\n\tPrint() string\n}\n\ntype Console struct{}\n\nfunc (c Console) Print() string {\n\treturn \"console\"\n}\n\nfunc (c Console) String() string {\n\treturn \"console\"\n}\n\ntype Scaled interface {\n\t~int | float64\n\tScale(factor int) int\n}\n\ntype Ruler struct{}\n\nfunc (r Ruler) Scale(factor int) int {\n\treturn factor\n}\n\ntype Writer interface {\n\tWrite(p []byte) int\n\tClose() error\n}\n\ntype File struct{}\n\nfunc (f File) Write(p []byte) int {\n\treturn 0\n}\n\nfunc (f File) Close() error {\n\treturn nil\n}\n\ntype Pinger interface {\n\tPing() string\n}\n\ntype Left struct{}\n\nfunc (l Left) Ping() string {\n\treturn \"left\"\n}\n\ntype Right struct{}\n\nfunc (r Right) Ping() string {\n\treturn \"right\"\n}\n\ntype Both struct {\n\tLeft\n\tRight\n}\n\ntype Upper struct {\n\tLeft\n}\n\ntype Lower struct {\n\tLeft\n}\n\ntype Diamond struct {\n\tUpper\n\tLower\n}\n\ntype Carrier struct {\n\tPinger\n}\n",
    ),
];

/// One concrete type and one interface, which is exactly one comparison.
///
/// The comparison ceiling is proved at zero rather than by a larger corpus: a
/// corpus stating one comparison refuses at a ceiling of none and publishes at
/// a ceiling of one, and no other count could explain either answer.
pub const LIMIT_INTERFACE: &[FixtureFile] = &[
    MANIFEST,
    (
        "repo/a.go",
        "package app\n\ntype Pinger interface {\n\tPing() string\n}\n\ntype Node struct{}\n\nfunc (n Node) Ping() string {\n\treturn \"node\"\n}\n",
    ),
];
