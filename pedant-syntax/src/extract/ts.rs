//! Declaration recognition over tree-sitter parse trees.
//!
//! Traversal, containment, naming, and selection are shared; only the node
//! kinds and the ownership questions behind them are per-language, so a
//! backend is one `match` arm rather than a trait implementation.

use std::ops::Range;

use crate::extract::select::UnitSelector;
use crate::language::SyntaxLanguage;
use crate::tree_sitter::{Node, node_text, walk_descendants};
use crate::unit::SourceUnitKind;

/// One recognized grammar node: the byte range to return and the node naming it.
///
/// The range rather than a node, because a declaration's text is not always one
/// node's extent: a Go specification may return its whole `type` declaration,
/// and a decorated class member opens at a decorator the grammar states as a
/// preceding sibling.
struct Declaration<'t> {
    kind: SourceUnitKind,
    range: Range<usize>,
    name: Option<Node<'t>>,
}

/// Parse `source` and offer every recognized declaration in it.
///
/// A missing tree or an error-bearing root is parser failure: nothing is
/// offered, even where recovery left a recognized declaration in the tree.
///
/// The parse binds a session rather than taking a bare tree, so this route and
/// the session's own answer read the same error rule from
/// [`ParsedSyntax::has_errors`](crate::tree_sitter::ParsedSyntax::has_errors)
/// and neither can drift from the other.
pub(crate) fn collect<'s>(
    source: &'s str,
    language: SyntaxLanguage,
    selector: &mut UnitSelector<'s>,
) {
    let Some(parsed) = crate::tree_sitter::parse_bound(source, language) else {
        return;
    };
    if parsed.has_errors() {
        return;
    }
    offer_declarations(parsed.root(), source, language, selector);
}

/// Offer every recognized declaration beneath `root` to `selector`.
///
/// The one recognizer both entry points share. `source` must be the exact
/// string `root`'s tree was parsed from, because a node's byte range indexes
/// it; [`collect`] parses that string itself and a session was bound to it.
pub(crate) fn offer_declarations<'s>(
    root: Node<'_>,
    source: &'s str,
    language: SyntaxLanguage,
    selector: &mut UnitSelector<'s>,
) {
    let bytes = source.as_bytes();
    walk_descendants(root, |node| {
        let Some(declaration) = recognize(node, language) else {
            return;
        };
        // Containment first: a declaration that misses the location needs no
        // name, and resolving one validates the whole declaration's text as
        // UTF-8. Traversal cannot prune here, so most declarations miss.
        if !selector.contains(&declaration.range) {
            return;
        }
        let name = declaration.name.map(|node| node_text(node, bytes));
        selector.keep(declaration.kind, name, declaration.range);
    });
}

/// The declaration `node` represents in `language`, if any.
///
/// Every variant names both arms — the matcher its feature enables and the
/// absence its feature leaves — so the match is exhaustive in every
/// configuration and a new [`SyntaxLanguage`] fails to compile here rather than
/// recognizing nothing.
fn recognize<'t>(node: Node<'t>, language: SyntaxLanguage) -> Option<Declaration<'t>> {
    match language {
        // Rust has no grammar here; its backend is `extract::rust`.
        SyntaxLanguage::Rust => None,
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
        #[cfg(feature = "ts-go")]
        SyntaxLanguage::Go => go(node),
        #[cfg(not(feature = "ts-go"))]
        SyntaxLanguage::Go => None,
        #[cfg(feature = "ts-bash")]
        SyntaxLanguage::Bash => bash(node),
        #[cfg(not(feature = "ts-bash"))]
        SyntaxLanguage::Bash => None,
    }
}

/// A declaration returning `range`'s text, named by `namer`'s `name` field.
fn declaration(range: Range<usize>, kind: SourceUnitKind, namer: Node<'_>) -> Declaration<'_> {
    Declaration {
        kind,
        range,
        name: namer.child_by_field_name("name"),
    }
}

/// Python: functions, classes, and the decorated form of either.
///
/// A decorated declaration returns the outer decorator text with the inner
/// declaration's kind and name.
#[cfg(feature = "ts-python")]
fn python(node: Node<'_>) -> Option<Declaration<'_>> {
    let inner = python_inner(node)?;
    let kind = match inner.kind() {
        "class_definition" => SourceUnitKind::Class,
        "function_definition" => python_function_kind(node),
        _ => return None,
    };
    Some(declaration(node.byte_range(), kind, inner))
}

/// The declaration a candidate node describes: itself, or the definition its
/// decorators wrap.
///
/// A definition a decorator already owns is not a candidate, because its
/// decorated form is the one that carries the full text.
#[cfg(feature = "ts-python")]
fn python_inner(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "decorated_definition" => node.child_by_field_name("definition"),
        "function_definition" | "class_definition" => (!owned_by_decorator(node)).then_some(node),
        _ => None,
    }
}

/// A Python function a class body declares directly is a method.
#[cfg(feature = "ts-python")]
fn python_function_kind(outer: Node<'_>) -> SourceUnitKind {
    match owner_is_class(outer) {
        true => SourceUnitKind::Method,
        false => SourceUnitKind::Function,
    }
}

/// Whether a decorator wraps `node`.
#[cfg(feature = "ts-python")]
fn owned_by_decorator(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "decorated_definition")
}

/// Whether a class body declares `outer` directly.
///
/// `outer` is the outermost form [`python_inner`] accepted — the
/// `decorated_definition`, or a definition no decorator wraps — so the
/// relationship that function established is read, not re-derived.
#[cfg(feature = "ts-python")]
fn owner_is_class(outer: Node<'_>) -> bool {
    outer
        .parent()
        .and_then(|body| body.parent())
        .is_some_and(|owner| owner.kind() == "class_definition")
}

/// JavaScript declarations.
#[cfg(feature = "ts-javascript")]
fn javascript(node: Node<'_>) -> Option<Declaration<'_>> {
    Some(js_declaration(node, javascript_kind(node.kind())?))
}

/// One JavaScript-family declaration: the widened range, the kind its grammar
/// node names, and the node that names it.
///
/// The one tail both the JavaScript and the TypeScript backend read, so the two
/// cannot disagree about how far a declaration's text reaches.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
fn js_declaration(node: Node<'_>, kind: SourceUnitKind) -> Declaration<'_> {
    declaration(js_declared_range(node), kind, node)
}

/// The JavaScript declaration set, shared with TypeScript and TSX.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
fn javascript_kind(kind: &str) -> Option<SourceUnitKind> {
    match kind {
        "function_declaration" | "generator_function_declaration" => Some(SourceUnitKind::Function),
        "method_definition" => Some(SourceUnitKind::Method),
        "class_declaration" => Some(SourceUnitKind::Class),
        _ => None,
    }
}

/// TypeScript and TSX add the abstract class, the type alias, and the enum to
/// the JavaScript set.
#[cfg(feature = "ts-typescript")]
fn typescript(node: Node<'_>) -> Option<Declaration<'_>> {
    let kind = match node.kind() {
        "abstract_class_declaration" => SourceUnitKind::Class,
        // An interface is not here: the model declares no variant for one.
        "type_alias_declaration" => SourceUnitKind::TypeAlias,
        "enum_declaration" => SourceUnitKind::Enum,
        other => javascript_kind(other)?,
    };
    Some(js_declaration(node, kind))
}

/// The byte range one JavaScript or TypeScript declaration returns.
///
/// The grammar states a declaration's modifiers outside the declaration node
/// itself, so the bare node loses text every other backend keeps — Python
/// widens to `decorated_definition`, Go to `type_declaration`, and a Rust span
/// already covers its attributes. Two shapes need widening:
///
/// - An `export_statement` introduces the declaration, so `export`,
///   `export default`, and any decorator the statement holds open the text.
/// - A decorator on a class member is a preceding sibling inside the
///   `class_body` rather than a child, so the range opens at the first of the
///   run. A bare class states its decorators as children and needs neither.
///
/// The result can be wider than the node, and selection compares byte length,
/// so an inner `method_definition` still beats the class that exports it.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
fn js_declared_range(node: Node<'_>) -> Range<usize> {
    let outer = node
        .parent()
        .filter(|parent| parent.kind() == "export_statement")
        .unwrap_or(node);
    let start = leading_decorator(outer).unwrap_or(outer).start_byte();
    start..outer.end_byte()
}

/// The first decorator of the run immediately preceding `node`, if any.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
fn leading_decorator(node: Node<'_>) -> Option<Node<'_>> {
    std::iter::successors(decorator_before(node), |current| decorator_before(*current)).last()
}

/// The decorator immediately preceding `node` among its siblings.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
fn decorator_before(node: Node<'_>) -> Option<Node<'_>> {
    node.prev_sibling()
        .filter(|sibling| sibling.kind() == "decorator")
}

/// Go functions, methods, and struct type specifications.
#[cfg(feature = "ts-go")]
fn go(node: Node<'_>) -> Option<Declaration<'_>> {
    match node.kind() {
        "function_declaration" => Some(declaration(
            node.byte_range(),
            SourceUnitKind::Function,
            node,
        )),
        "method_declaration" => Some(declaration(node.byte_range(), SourceUnitKind::Method, node)),
        "type_spec" => go_struct(node),
        _ => None,
    }
}

/// A Go type specification is a unit only when it declares a struct;
/// interfaces and aliases are not units.
///
/// The unit is the specification, not its declaration, so each struct in a
/// grouped `type (...)` is its own unit and a non-struct beside it stays
/// absent.
#[cfg(feature = "ts-go")]
fn go_struct(node: Node<'_>) -> Option<Declaration<'_>> {
    let declared = node.child_by_field_name("type")?;
    (declared.kind() == "struct_type")
        .then(|| declaration(go_declared_range(node), SourceUnitKind::Struct, node))
}

/// The byte range one type specification returns.
///
/// A sole ungrouped specification returns its whole declaration, so the `type`
/// keyword opens the text. A specification inside `type (...)` returns only
/// its own range.
#[cfg(feature = "ts-go")]
fn go_declared_range(spec: Node<'_>) -> Range<usize> {
    spec.parent()
        .filter(|parent| parent.kind() == "type_declaration" && go_is_sole_spec(spec))
        .unwrap_or(spec)
        .byte_range()
}

/// Whether a specification is all its `type` declaration states.
///
/// The grammar states `type_declaration` as `seq('type', choice(spec, alias,
/// seq('(', ..., ')')))`, so an ungrouped specification closes its declaration
/// and a grouped one is always followed by at least the closing parenthesis.
/// One sibling read answers that. Scanning the children for the opening
/// parenthesis allocates a tree-sitter cursor per specification, and reading a
/// fixed child index in its place would answer wrongly for `type /* c */ (`,
/// where the comment the grammar admits as an extra displaces the parenthesis.
#[cfg(feature = "ts-go")]
fn go_is_sole_spec(spec: Node<'_>) -> bool {
    spec.next_sibling().is_none()
}

/// Bash function definitions, with or without the `function` keyword.
#[cfg(feature = "ts-bash")]
fn bash(node: Node<'_>) -> Option<Declaration<'_>> {
    match node.kind() {
        "function_definition" => Some(declaration(
            node.byte_range(),
            SourceUnitKind::Function,
            node,
        )),
        _ => None,
    }
}
