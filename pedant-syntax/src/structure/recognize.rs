//! Which grammar nodes state a logical structure, and what they state.
//!
//! One table per language row of the structure contract, and the only one in
//! this crate: the enclosing-unit recognizer reads these same tables and
//! narrows them to the kinds the unit model declares, so no grammar node kind
//! is written down twice. The ranges a declaration returns are not restated
//! here either — the extraction backend already owns how far a decorated,
//! exported, or grouped declaration's text reaches, and every reader takes that
//! one answer.

use std::ops::Range;

use pedant_types::StructureKind;

use crate::language::SyntaxLanguage;
use crate::span::LineSpan;
use crate::structure::builder::lines_between;
use crate::tree_sitter::Node;

/// One recognized structure: what it declares, the text it returns, the lines
/// that text covers, the node naming it, and whether that text holds a body.
///
/// The lines travel with the bytes because the grammar already reported them. A
/// reader that resolved them afterwards would index a line table this crate
/// would have to build over the whole source first, and would then have to
/// rediscover which node the widened range opens at.
///
/// The body travels with them for the same reason the ranges do: it is a fact
/// about a grammar node, and the enclosing-unit reader needs it to decide
/// whether the recognized text is a declaration a caller can be handed. Carried
/// as a value rather than left for that reader to derive, because deriving it
/// meant writing a node kind down a second time, outside the table — and a
/// grammar rename would then break the narrowing in silence instead of failing
/// at the row that names the kind.
pub(crate) struct Recognized<'tree> {
    pub(crate) kind: StructureKind,
    pub(crate) bytes: Range<usize>,
    pub(crate) lines: LineSpan,
    pub(crate) name: Option<Node<'tree>>,
    /// Whether the returned text holds what the declaration defines, rather
    /// than a signature that stops before it.
    pub(crate) body: bool,
}

/// The byte and line extent of the text opening at `from` and closing at `to`.
///
/// One reading of how far a declaration reaches, in both dimensions at once, so
/// a widened range and the lines beside it cannot name different text.
fn extent(from: Node<'_>, to: Node<'_>) -> (Range<usize>, LineSpan) {
    let end = to.end_position();
    (
        from.start_byte()..to.end_byte(),
        lines_between(from.start_position().row, end.row, end.column),
    )
}

/// The structure `node` states in `language`, if any.
///
/// Every variant names both arms — the table its feature enables and the
/// absence its feature leaves — so the match is exhaustive in every
/// configuration and a new [`SyntaxLanguage`] fails to compile here rather than
/// recognizing nothing.
pub(crate) fn recognize<'tree>(
    node: Node<'tree>,
    language: SyntaxLanguage,
) -> Option<Recognized<'tree>> {
    match language {
        // Rust has no grammar here; its structures come from `structure::rust`.
        SyntaxLanguage::Rust => None,
        // Go declarations belong to `GoFileFacts`, which `structure::go`
        // projects, so no Go node is recognized here in any configuration.
        SyntaxLanguage::Go => None,
        #[cfg(feature = "ts-python")]
        SyntaxLanguage::Python => python(node),
        #[cfg(not(feature = "ts-python"))]
        SyntaxLanguage::Python => None,
        #[cfg(feature = "ts-javascript")]
        SyntaxLanguage::JavaScript => javascript(node),
        #[cfg(not(feature = "ts-javascript"))]
        SyntaxLanguage::JavaScript => None,
        #[cfg(feature = "ts-typescript")]
        SyntaxLanguage::TypeScript | SyntaxLanguage::Tsx => typescript(node),
        #[cfg(not(feature = "ts-typescript"))]
        SyntaxLanguage::TypeScript | SyntaxLanguage::Tsx => None,
        #[cfg(feature = "ts-bash")]
        SyntaxLanguage::Bash => bash(node),
        #[cfg(not(feature = "ts-bash"))]
        SyntaxLanguage::Bash => None,
    }
}

/// Whether `language` states its whole source as one module structure.
///
/// A Python or ECMAScript file is a module the source declares no node for, so
/// the inventory states it from the file itself. Rust names its modules with
/// `mod` items, Go names its package with a clause, and Bash declares neither.
pub(super) fn source_is_a_module(language: SyntaxLanguage) -> bool {
    match language {
        SyntaxLanguage::Python
        | SyntaxLanguage::JavaScript
        | SyntaxLanguage::TypeScript
        | SyntaxLanguage::Tsx => true,
        SyntaxLanguage::Rust | SyntaxLanguage::Go | SyntaxLanguage::Bash => false,
    }
}

/// One structure covering exactly `node`, named by `namer`'s `name` field.
///
/// Every Python and Bash form this table recognizes writes what it defines:
/// neither grammar states a bodiless declaration these rows name.
#[cfg(any(feature = "ts-python", feature = "ts-bash"))]
fn named<'tree>(node: Node<'tree>, kind: StructureKind, namer: Node<'tree>) -> Recognized<'tree> {
    let (bytes, lines) = extent(node, node);
    Recognized {
        kind,
        bytes,
        lines,
        name: namer.child_by_field_name("name"),
        body: true,
    }
}

/// Python: functions, async functions, classes, and the decorated form of
/// either.
#[cfg(feature = "ts-python")]
fn python(node: Node<'_>) -> Option<Recognized<'_>> {
    let inner = crate::extract::ts::python_inner(node)?;
    let kind = python_kind(inner.kind(), crate::extract::ts::owner_is_class(node))?;
    Some(named(node, kind, inner))
}

/// What one Python definition declares, given whether a class body owns it.
///
/// The ownership answer is read from the extraction backend rather than
/// re-derived, so the two readers cannot disagree about which `def` is a
/// method.
#[cfg(feature = "ts-python")]
fn python_kind(inner: &str, owned_by_class: bool) -> Option<StructureKind> {
    match (inner, owned_by_class) {
        ("class_definition", _) => Some(StructureKind::Class),
        ("function_definition", true) => Some(StructureKind::Method),
        ("function_definition", false) => Some(StructureKind::Function),
        _ => None,
    }
}

/// JavaScript: declared functions and generators, classes, methods, and
/// declared fields.
#[cfg(feature = "ts-javascript")]
fn javascript(node: Node<'_>) -> Option<Recognized<'_>> {
    // Every declaration the base grammar states here writes its body.
    Some(js_structure(node, javascript_kind(node.kind())?, true))
}

/// One ECMAScript-family structure: the widened range, the kind its grammar
/// node names, the node that names it, and whether its text holds a body.
///
/// The one tail the JavaScript and TypeScript tables share, so the two cannot
/// disagree about how far a structure's text reaches or which child names it.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
fn js_structure(node: Node<'_>, kind: StructureKind, body: bool) -> Recognized<'_> {
    let (from, to) = crate::extract::ts::js_declared_bounds(node);
    let (bytes, lines) = extent(from, to);
    // A class field is named by its `property`; every other form by its `name`.
    // One lookup with a fallback rather than a second kind table, because the
    // two field spellings differ only in that word.
    let name = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("property"));
    Recognized {
        kind,
        bytes,
        lines,
        name,
        body,
    }
}

/// The JavaScript structure set, shared with TypeScript and TSX.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
fn javascript_kind(kind: &str) -> Option<StructureKind> {
    match kind {
        "function_declaration" | "generator_function_declaration" => Some(StructureKind::Function),
        "method_definition" => Some(StructureKind::Method),
        "class_declaration" => Some(StructureKind::Class),
        "field_definition" => Some(StructureKind::Field),
        _ => None,
    }
}

/// TypeScript and TSX add interfaces, type aliases, enums, namespaces, abstract
/// classes, declared fields, and members declared without bodies.
#[cfg(feature = "ts-typescript")]
fn typescript(node: Node<'_>) -> Option<Recognized<'_>> {
    let (kind, body) = typescript_kind(node.kind())?;
    Some(js_structure(node, kind, body))
}

/// What one TypeScript node declares, and whether its text holds a body.
///
/// The two facts sit in one row because both are read off the node kind, and
/// this is the one place a TypeScript node kind is written down. `abstract
/// run(): number;` is the row this pair exists for: the type declares a method,
/// so the structure is a method, but the text stops at the semicolon.
#[cfg(feature = "ts-typescript")]
fn typescript_kind(kind: &str) -> Option<(StructureKind, bool)> {
    match kind {
        "abstract_class_declaration" => Some((StructureKind::Class, true)),
        "interface_declaration" => Some((StructureKind::Interface, true)),
        "type_alias_declaration" => Some((StructureKind::TypeAlias, true)),
        "enum_declaration" => Some((StructureKind::Enum, true)),
        // `namespace X {}` and the legacy `module X {}` are one construct with
        // two spellings; the model states no namespace of its own, so both are
        // the module they open.
        "internal_module" | "module" => Some((StructureKind::Module, true)),
        "public_field_definition" => Some((StructureKind::Field, true)),
        "abstract_method_signature" => Some((StructureKind::Method, false)),
        "method_signature" => Some((StructureKind::Method, false)),
        "property_signature" => Some((StructureKind::Field, false)),
        other => Some((javascript_kind(other)?, true)),
    }
}

/// Bash: function definitions, with or without the `function` keyword.
#[cfg(feature = "ts-bash")]
fn bash(node: Node<'_>) -> Option<Recognized<'_>> {
    match node.kind() {
        "function_definition" => Some(named(node, StructureKind::Function, node)),
        _ => None,
    }
}
