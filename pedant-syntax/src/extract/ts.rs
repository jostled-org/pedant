//! Declaration recognition over tree-sitter parse trees.
//!
//! Traversal, containment, naming, and selection are shared, and so is the
//! grammar table: which node states a declaration, which child names it, and
//! how far its text reaches all come from `structure::recognize`, the crate's
//! one per-language table. A unit is that recognition narrowed to the kinds the
//! unit model declares.
//!
//! What stays here is the shape of a node the table cannot state for itself:
//! whether a Python definition is the one a decorator wraps, whether a class
//! body owns it, and how far an exported or decorated ECMAScript declaration
//! reaches. Those answer the same way for both readers, so the table calls
//! them.

#[cfg(feature = "_ts_generic")]
use std::ops::Range;

use crate::extract::select::UnitSelector;
use crate::language::SyntaxLanguage;
#[cfg(feature = "_ts_generic")]
use crate::structure::recognize::Recognized;
use crate::tree_sitter::Node;
#[cfg(feature = "_ts_generic")]
use crate::tree_sitter::{node_text, walk_descendants};
#[cfg(feature = "_ts_generic")]
use crate::unit::SourceUnitKind;

// Why an offering refuses.
//
// One backend can. The Go fact inventory runs beneath two ceilings and answers
// with a `GoFactError` rather than an empty inventory, because an empty one
// reads as "this file declares nothing". Every other backend answers by
// recognizing nothing, which is a real answer: a `Declaration` is the whole of
// what the shared recognizer can say.
//
// A build linking no Go grammar has no refusal to name, so the name is
// uninhabited there and every offering below is `Ok` by construction. One name
// rather than a second copy of the two functions that carry it.
#[cfg(feature = "ts-go")]
use crate::go::GoFactError as DeclarationRefusal;
#[cfg(not(feature = "ts-go"))]
use std::convert::Infallible as DeclarationRefusal;

/// One recognized grammar node: the byte range to return and the node naming it.
///
/// The range rather than a node, because a declaration's text is not always one
/// node's extent: a decorated class member opens at a decorator the grammar
/// states as a preceding sibling.
#[cfg(feature = "_ts_generic")]
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
) -> Result<(), DeclarationRefusal> {
    let Some(parsed) = crate::tree_sitter::parse_bound(source, language) else {
        return Ok(());
    };
    match parsed.has_errors() {
        true => Ok(()),
        false => offer_declarations(parsed.root(), source, language, selector),
    }
}

/// Offer every recognized declaration beneath `root` to `selector`.
///
/// The one recognizer both entry points share. `source` must be the exact
/// string `root`'s tree was parsed from, because a node's byte range indexes
/// it; [`collect`] parses that string itself and a session was bound to it.
///
/// Go is routed away from the walk below before it starts. Its declarations are
/// part of [`GoFileFacts`](crate::go::GoFileFacts), which capability
/// attribution and Go resolution both read, so recognizing them a second time
/// here would be a second grammar mapping that could answer differently. One
/// `match` decides that, so the routing and the standing down are one answer:
/// recognizing nothing for Go would still cost a whole-tree traversal.
pub(crate) fn offer_declarations<'s>(
    root: Node<'_>,
    source: &'s str,
    language: SyntaxLanguage,
    selector: &mut UnitSelector<'s>,
) -> Result<(), DeclarationRefusal> {
    match language {
        #[cfg(feature = "ts-go")]
        SyntaxLanguage::Go => crate::go::offer_unit_declarations(root, source, selector),
        #[cfg(feature = "_ts_generic")]
        other => offer_recognized(root, source, other, selector),
        #[cfg(not(feature = "_ts_generic"))]
        _ => Ok(()),
    }
}

/// Offer every declaration the shared recognizer names beneath `root`.
///
/// Absent from a build whose only grammar is Go, which the recognizer answers
/// for nothing: the walk would visit every node to recognize none of them.
///
/// Answers `Ok` in every build it exists in. A `Declaration` is the whole of
/// what this recognizer can say, and a language it holds no matcher for
/// recognizes nothing rather than refusing.
#[cfg(feature = "_ts_generic")]
fn offer_recognized<'s>(
    root: Node<'_>,
    source: &'s str,
    language: SyntaxLanguage,
    selector: &mut UnitSelector<'s>,
) -> Result<(), DeclarationRefusal> {
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
    Ok(())
}

/// The declaration `node` represents in `language`, if any.
///
/// One table answers for every language, and it is the structure recognizer's:
/// the node kinds, the child that names each one, and the byte range each
/// returns are stated there once. A second table here is what let the two
/// readers disagree about which `def` is a method and how far an exported
/// class's text reaches.
///
/// The per-language exhaustiveness that table states — every
/// [`SyntaxLanguage`] naming both the matcher its feature enables and the
/// absence its feature leaves — covers this route too, because this route is
/// that route.
#[cfg(feature = "_ts_generic")]
fn recognize<'t>(node: Node<'t>, language: SyntaxLanguage) -> Option<Declaration<'t>> {
    let found = crate::structure::recognize::recognize(node, language)?;
    Some(Declaration {
        kind: unit_kind(&found)?,
        range: found.bytes,
        name: found.name,
    })
}

/// The unit one recognized structure declares, if this model declares one.
///
/// The kind alone answers for every recognized node but one. A TypeScript
/// `abstract run(): number;` is recognized as a `StructureKind::Method` and the
/// structure inventory states it as one, but a source unit carries the
/// declaration's own text, and a signature with no body would return a single
/// line in place of the type that declares it. A reader inside one reads the
/// abstract class instead — the answer a Go interface method already gives.
///
/// Which recognized form that is comes from the table as a value. Re-asking the
/// node for its kind here would write a grammar node kind down a second time,
/// outside the one table that states them, and a grammar rename would then stop
/// narrowing with nothing red.
#[cfg(feature = "_ts_generic")]
fn unit_kind(found: &Recognized<'_>) -> Option<SourceUnitKind> {
    match found.body {
        true => SourceUnitKind::of(found.kind),
        false => None,
    }
}

/// The declaration a candidate node describes: itself, or the definition its
/// decorators wrap.
///
/// A definition a decorator already owns is not a candidate, because its
/// decorated form is the one that carries the full text.
#[cfg(feature = "ts-python")]
pub(crate) fn python_inner(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "decorated_definition" => node.child_by_field_name("definition"),
        "function_definition" | "class_definition" => (!owned_by_decorator(node)).then_some(node),
        _ => None,
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
pub(crate) fn owner_is_class(outer: Node<'_>) -> bool {
    outer
        .parent()
        .and_then(|body| body.parent())
        .is_some_and(|owner| owner.kind() == "class_definition")
}

/// The nodes one JavaScript or TypeScript declaration's returned text opens at
/// and closes at.
///
/// The grammar states a declaration's modifiers outside the declaration node
/// itself, so the bare node loses text every other backend keeps — Python
/// widens to `decorated_definition`, Go to `type_declaration`, and a Rust span
/// already covers its attributes. Two shapes need widening:
///
/// - An `export_statement` introduces the declaration, so `export`,
///   `export default`, and any decorator the statement holds open the text.
/// - A decorator on a class member is a preceding sibling inside the
///   `class_body` rather than a child, so the text opens at the first of the
///   run. A bare class states its decorators as children and needs neither.
///
/// The pair rather than a byte range, because both readers of this answer want
/// the lines the text covers as well as the bytes, and the grammar already
/// reports each node's position: returning the range alone would leave the
/// caller to rediscover which nodes the widened extent runs between.
///
/// The extent can be wider than the node, and selection compares byte length,
/// so an inner `method_definition` still beats the class that exports it.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
pub(crate) fn js_declared_bounds<'t>(node: Node<'t>) -> (Node<'t>, Node<'t>) {
    let outer = node
        .parent()
        .filter(|parent| parent.kind() == "export_statement")
        .unwrap_or(node);
    (leading_decorator(outer).unwrap_or(outer), outer)
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
