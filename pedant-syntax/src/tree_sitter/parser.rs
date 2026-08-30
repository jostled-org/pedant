//! Grammar selection and the crate's only tree-sitter parser.
//!
//! Every tree this crate produces is built here. A session reads the tree this
//! module handed it and never constructs a parser of its own, so "how many
//! times was this source parsed" is a question one module answers.

use ::tree_sitter::{Parser, Tree};

use crate::language::SyntaxLanguage;
use crate::tree_sitter::session::ParsedSyntax;

/// Parse source code with the grammar for `language`.
///
/// Returns `None` when the language has no enabled grammar in this build and
/// when the parser itself fails. Never falls back to another grammar. A
/// recovered tree carrying error nodes is still a tree: this helper returns it.
pub fn parse(source: &[u8], language: SyntaxLanguage) -> Option<Tree> {
    let mut parser = Parser::new();
    let selected = parser.set_language(&grammar(language)?);
    // The two `?` above and below mean different things. `grammar` reports the
    // absence this build chose; a grammar it did link failing to load is an ABI
    // mismatch between that grammar and the tree-sitter core, which is a build
    // misconfiguration rather than a language this build omits.
    debug_assert!(
        selected.is_ok(),
        "a linked grammar matches the tree-sitter ABI"
    );
    selected.ok()?;
    parser.parse(source, None)
}

/// Parse `source` into a [`ParsedSyntax`] session bound to that exact string.
///
/// One call is one parse. The returned session holds the tree beside the source
/// it was built from, so a caller that needs both structured detection and
/// declaration anchors asks the same session twice instead of parsing twice.
///
/// Returns `None` for the same two absences [`parse`] reports — a grammar this
/// build does not link, and a parser that produced no tree — and synthesizes no
/// fallback tree for either. A recovered tree carrying error nodes binds
/// normally; [`ParsedSyntax::has_errors`] reports it.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "ts-python")]
/// # {
/// use pedant_syntax::{Location, SourceUnitKind, SyntaxLanguage, tree_sitter::parse_bound};
///
/// let source = "def run():\n    import socket\n";
/// let parsed = parse_bound(source, SyntaxLanguage::Python).expect("a parse session");
///
/// assert!(!parsed.has_errors());
/// let anchor = parsed
///     .enclosing_unit_anchor(Location { line: 2, column: Some(5) })
///     .expect("the enclosing function");
/// assert_eq!(anchor.kind, SourceUnitKind::Function);
/// assert_eq!(anchor.name.as_deref(), Some("run"));
/// assert_eq!(anchor.start.line, 1);
/// # }
/// ```
pub fn parse_bound(source: &str, language: SyntaxLanguage) -> Option<ParsedSyntax<'_>> {
    let tree = parse(source.as_bytes(), language)?;
    Some(ParsedSyntax::bind(source, language, tree))
}

/// Whether this build links a grammar for `language`.
///
/// The one honest difference between "no parser here" and "the parser found
/// nothing": both leave [`parse_bound`] absent, and a caller that must not read
/// absence as "this source declares nothing" needs to tell them apart.
pub(crate) fn links_grammar(language: SyntaxLanguage) -> bool {
    grammar(language).is_some()
}

/// The enabled tree-sitter grammar for `language`, if this build has one.
///
/// Every variant names both arms — the grammar its feature enables and the
/// absence its feature leaves — so the match is exhaustive in every
/// configuration and a new [`SyntaxLanguage`] fails to compile here rather than
/// parsing as nothing.
fn grammar(language: SyntaxLanguage) -> Option<::tree_sitter::Language> {
    match language {
        // Rust parses through `syn`; it selects no grammar in any build.
        SyntaxLanguage::Rust => None,
        #[cfg(feature = "ts-python")]
        SyntaxLanguage::Python => Some(tree_sitter_python::LANGUAGE.into()),
        #[cfg(not(feature = "ts-python"))]
        SyntaxLanguage::Python => None,
        #[cfg(feature = "ts-javascript")]
        SyntaxLanguage::JavaScript => Some(tree_sitter_javascript::LANGUAGE.into()),
        #[cfg(not(feature = "ts-javascript"))]
        SyntaxLanguage::JavaScript => None,
        #[cfg(feature = "ts-typescript")]
        SyntaxLanguage::TypeScript => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        #[cfg(feature = "ts-typescript")]
        SyntaxLanguage::Tsx => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        #[cfg(not(feature = "ts-typescript"))]
        SyntaxLanguage::TypeScript | SyntaxLanguage::Tsx => None,
        #[cfg(feature = "ts-go")]
        SyntaxLanguage::Go => Some(tree_sitter_go::LANGUAGE.into()),
        #[cfg(not(feature = "ts-go"))]
        SyntaxLanguage::Go => None,
        #[cfg(feature = "ts-bash")]
        SyntaxLanguage::Bash => Some(tree_sitter_bash::LANGUAGE.into()),
        #[cfg(not(feature = "ts-bash"))]
        SyntaxLanguage::Bash => None,
    }
}
