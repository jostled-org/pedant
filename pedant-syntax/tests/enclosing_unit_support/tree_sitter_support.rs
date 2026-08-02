//! The tree-sitter support surface: grammar selection, recovery trees, and
//! the constructs no backend recognizes.

use pedant_syntax::tree_sitter::{Tree, node_text, parse, walk_descendants};
use pedant_syntax::{SyntaxLanguage, enclosing_unit};

use crate::fixture_support::{
    assert_covered, assert_every_disabled_tree_sitter_backend_skipped, extraction_enabled,
    tree_sitter_languages,
};
use crate::positions::point_of;

/// What one row of a case table covers, for the coverage guard's diagnostics.
const SUBJECT: &str = "tree-sitter backend";

/// A grammar case: source that parses cleanly only under its own grammar,
/// the grammar's root node kind, and a node kind unique to that grammar.
struct GrammarCase {
    source: &'static str,
    root_kind: &'static str,
    marker_kind: &'static str,
    marker_text: &'static str,
}

/// Malformed source whose recovery tree still holds a whole declaration.
///
/// Named rather than a tuple of four strings: `declaration_kind`,
/// `declaration_text`, and `probe` are all bare text, so a transposition at the
/// point of authoring would type-check.
struct MalformedCase {
    source: &'static str,
    /// The node kind recovery keeps.
    declaration_kind: &'static str,
    /// That node's text, stated rather than merely required to exist, so
    /// recovery that keeps the right kind with the wrong extent fails here.
    declaration_text: &'static str,
    /// A substring inside the recovered declaration.
    probe: &'static str,
}

/// Clean source holding a construct no backend recognizes as a declaration.
struct UnsupportedCase {
    source: &'static str,
    /// A substring inside the unrecognized construct.
    probe: &'static str,
}

/// Everything one tree-sitter language contributes, in one row.
///
/// Three tables each keyed by their own `language` field were three chances to
/// key them apart: a language stated in two and forgotten in the third left the
/// alignment to a test rather than to the shape. One row states the language
/// once, so the three cases cannot disagree about which language they describe,
/// and the count below asks the one question left — that every language has a
/// row.
struct LanguageCases {
    language: SyntaxLanguage,
    grammar: GrammarCase,
    malformed: MalformedCase,
    unsupported: UnsupportedCase,
}

const CASES: [LanguageCases; 6] = [
    LanguageCases {
        language: SyntaxLanguage::Python,
        grammar: GrammarCase {
            source: "def outer(value):\n    return value\n",
            root_kind: "module",
            marker_kind: "function_definition",
            marker_text: "def outer(value):\n    return value",
        },
        malformed: MalformedCase {
            source: "def good(value):\n    return value\n\ndef broken(:\n    pass\n",
            declaration_kind: "function_definition",
            declaration_text: "def good(value):\n    return value",
            probe: "return value",
        },
        unsupported: UnsupportedCase {
            source: "total = 0\nfor index in range(3):\n    total += index\n",
            probe: "total += index",
        },
    },
    LanguageCases {
        language: SyntaxLanguage::JavaScript,
        grammar: GrammarCase {
            source: "function outer(value) { return value; }\n",
            root_kind: "program",
            marker_kind: "function_declaration",
            marker_text: "function outer(value) { return value; }",
        },
        malformed: MalformedCase {
            source: "function good(value) {\n  return value;\n}\n\nfunction broken( {\n",
            declaration_kind: "function_declaration",
            declaration_text: "function good(value) {\n  return value;\n}",
            probe: "return value;",
        },
        unsupported: UnsupportedCase {
            source: "const build = function (count) {\n  return count + 1;\n};\n",
            probe: "return count + 1;",
        },
    },
    LanguageCases {
        language: SyntaxLanguage::TypeScript,
        grammar: GrammarCase {
            source: "function outer(value: number): number { return value; }\n",
            root_kind: "program",
            marker_kind: "type_annotation",
            marker_text: ": number",
        },
        malformed: MalformedCase {
            source: "function good(value: number) {\n  return value;\n}\n\nfunction broken( {\n",
            declaration_kind: "function_declaration",
            declaration_text: "function good(value: number) {\n  return value;\n}",
            probe: "return value;",
        },
        unsupported: UnsupportedCase {
            source: "interface Shape {\n  area(): number;\n}\n",
            probe: "area(): number;",
        },
    },
    LanguageCases {
        language: SyntaxLanguage::Tsx,
        grammar: GrammarCase {
            source: "const view = () => <div className=\"row\" />;\n",
            root_kind: "program",
            marker_kind: "jsx_self_closing_element",
            marker_text: "<div className=\"row\" />",
        },
        malformed: MalformedCase {
            source: "function Good(label: string) {\n  return <b>{label}</b>;\n}\n\nfunction Broken( {\n",
            declaration_kind: "function_declaration",
            declaration_text: "function Good(label: string) {\n  return <b>{label}</b>;\n}",
            probe: "return <b>",
        },
        unsupported: UnsupportedCase {
            source: "const view = (label: string) => <b>{label}</b>;\n",
            probe: "<b>",
        },
    },
    LanguageCases {
        language: SyntaxLanguage::Go,
        grammar: GrammarCase {
            source: "package main\n\nfunc outer() int { return 1 }\n",
            root_kind: "source_file",
            marker_kind: "function_declaration",
            marker_text: "func outer() int { return 1 }",
        },
        malformed: MalformedCase {
            source: "package main\n\nfunc good() int {\n    return 1\n}\n\nfunc broken( {\n",
            declaration_kind: "function_declaration",
            declaration_text: "func good() int {\n    return 1\n}",
            probe: "return 1",
        },
        unsupported: UnsupportedCase {
            source: "package main\n\ntype Alias = int\n\nvar total = 1\n",
            probe: "var total = 1",
        },
    },
    LanguageCases {
        language: SyntaxLanguage::Bash,
        grammar: GrammarCase {
            source: "outer() {\n  echo hi\n}\n",
            root_kind: "program",
            marker_kind: "function_definition",
            marker_text: "outer() {\n  echo hi\n}",
        },
        malformed: MalformedCase {
            source: "good() {\n  echo hi\n}\n\nbroken() {\n",
            declaration_kind: "function_definition",
            declaration_text: "good() {\n  echo hi\n}",
            probe: "echo hi",
        },
        unsupported: UnsupportedCase {
            source: "if [ -n \"$1\" ]; then\n  echo hi\nfi\n",
            probe: "echo hi",
        },
    },
];

/// Text of the first descendant of `tree` with `kind`, in depth-first order.
///
/// Borrows `source`, which outlives the tree, so a caller keeps the matched
/// text without allocating. The one traversal helper here: absence and text
/// answer the same question, and a caller that already holds a tree never
/// parses a second time to ask it.
fn first_text_of_kind<'s>(tree: &Tree, kind: &str, source: &'s [u8]) -> Option<&'s str> {
    let mut found: Option<&'s str> = None;
    // The whole tree is walked even after the match. `walk_descendants` takes
    // an `FnMut` visitor and reads no return value, so the callback signature
    // offers no early exit; `or_else` keeps the first match instead. The trees
    // here are single-declaration snippets, so the full walk costs nothing.
    walk_descendants(tree.root_node(), |node| {
        found = found.or_else(|| (node.kind() == kind).then(|| node_text(node, source)));
    });
    found
}

/// The row for `language`, which the table names once.
///
/// Gated with its one caller: only the cross-dialect test reaches a row by
/// language rather than by iterating the table.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
fn cases_for(language: SyntaxLanguage) -> LanguageCases {
    CASES
        .into_iter()
        .find(|row| row.language == language)
        .unwrap_or_else(|| panic!("{language:?} has a row"))
}

/// The table counted in place: it already holds the languages, so asking how
/// often one appears needs no second copy of the column.
///
/// One row carries all three cases, so this is the whole coverage question —
/// a language with a row has a grammar case, a malformed case, and an
/// unsupported case, or the row does not compile.
#[test]
fn every_tree_sitter_language_has_one_row() {
    let listed = CASES.map(|row| row.language);
    for language in tree_sitter_languages() {
        assert_eq!(
            listed.iter().filter(|row| **row == language).count(),
            1,
            "{language:?} appears once in the case table"
        );
    }
}

/// `node_text` answers for a buffer it cannot read the node's range out of.
///
/// The helper is published API with twelve call sites in `pedant-lang`, and it
/// has two ways to answer nothing: a range the buffer does not hold, and a
/// range that is not valid UTF-8. Both are stated here, because a caller that
/// passes a different buffer than [`parse`] consumed can produce either.
/// Library source raises no panic.
#[test]
fn node_text_of_an_unreadable_buffer_is_empty() {
    let mut proved = 0_usize;
    for row in &CASES {
        let language = row.language;
        if !extraction_enabled(language) {
            continue;
        }
        let bytes = row.grammar.source.as_bytes();
        let tree = parse(bytes, language).unwrap_or_else(|| panic!("{language:?} parses"));
        let root = tree.root_node();
        // The root covers text, so every empty answer below is the failure
        // branch rather than an empty range answering emptily.
        assert!(
            !node_text(root, bytes).is_empty(),
            "{language:?} root covers the source it parsed"
        );
        assert_eq!(
            node_text(root, &bytes[..1]),
            "",
            "{language:?} reads no text from a buffer shorter than the root"
        );
        assert_eq!(
            node_text(root, b""),
            "",
            "{language:?} reads no text from an empty buffer"
        );
        // Same length, so the range is in bounds and only the encoding
        // rejects it: 0xFF starts no UTF-8 sequence.
        let invalid = vec![0xFF_u8; bytes.len()];
        assert_eq!(
            node_text(root, &invalid),
            "",
            "{language:?} reads no text from a buffer that is not UTF-8"
        );
        proved += 1;
    }
    assert_covered(proved, tree_sitter_languages(), SUBJECT);
}

/// A grammar this build omits selects nothing, and Rust selects nothing in
/// every build.
///
/// The loop body runs only for a disabled backend, so the all-features
/// configuration reaches none of it. The count guard makes the run state that:
/// it names how many backends this configuration disabled, so a passing run
/// says which configuration it proved rather than staying silent.
#[test]
fn disabled_backend_returns_none() {
    let mut skipped = 0_usize;
    for row in &CASES {
        let language = row.language;
        if !extraction_enabled(language) {
            assert!(
                parse(row.grammar.source.as_bytes(), language).is_none(),
                "{language:?} is disabled in this configuration"
            );
            skipped += 1;
        }
    }
    assert_every_disabled_tree_sitter_backend_skipped(skipped);
    assert!(
        parse(b"fn main() {}", SyntaxLanguage::Rust).is_none(),
        "Rust never selects a tree-sitter grammar"
    );
}

/// Each grammar parses its own source, and the traversal starts below the root.
///
/// `walk_descendants` deliberately skips the node it is handed, so a visitor
/// counting declarations never counts the whole file as one. The root kind is
/// unique to the root in every grammar here, so asking the traversal for it and
/// getting nothing states that rule.
#[test]
fn each_enabled_language_parses_with_its_grammar() {
    let mut proved = 0_usize;
    for row in &CASES {
        let language = row.language;
        if !extraction_enabled(language) {
            continue;
        }
        let case = &row.grammar;
        let bytes = case.source.as_bytes();
        let tree = parse(bytes, language).unwrap_or_else(|| panic!("{language:?} parses"));
        let root = tree.root_node();
        assert_eq!(root.kind(), case.root_kind, "{language:?} root");
        assert!(!root.has_error(), "{language:?} source is clean");
        assert_eq!(
            first_text_of_kind(&tree, case.marker_kind, bytes),
            Some(case.marker_text),
            "{language:?} exposes its grammar-specific node"
        );
        assert!(
            first_text_of_kind(&tree, case.root_kind, bytes).is_none(),
            "{language:?} descendants exclude the root the walk started from"
        );
        proved += 1;
    }
    assert_covered(proved, tree_sitter_languages(), SUBJECT);
}

/// A grammar fed another dialect's source does not quietly accept it.
///
/// Each half needs only the grammar it parses with: the other dialect's source
/// is a constant. The cfg keeps a build that links neither from running this
/// with nothing to assert.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
#[test]
fn mismatched_grammars_reject_each_other() {
    if extraction_enabled(SyntaxLanguage::JavaScript) {
        let typed = cases_for(SyntaxLanguage::TypeScript).grammar.source;
        let tree =
            parse(typed.as_bytes(), SyntaxLanguage::JavaScript).expect("javascript grammar parses");
        assert!(
            tree.root_node().has_error(),
            "the JavaScript grammar rejects TypeScript annotations"
        );
    }
    if extraction_enabled(SyntaxLanguage::Tsx) {
        let jsx = cases_for(SyntaxLanguage::Tsx).grammar;
        let tree = parse(jsx.source.as_bytes(), SyntaxLanguage::TypeScript)
            .expect("typescript grammar parses");
        assert!(
            first_text_of_kind(&tree, jsx.marker_kind, jsx.source.as_bytes()).is_none(),
            "the TypeScript grammar has no JSX element node"
        );
    }
}

#[test]
fn parse_preserves_error_tree_while_extraction_rejects_it() {
    let mut proved = 0_usize;
    for row in &CASES {
        let language = row.language;
        if !extraction_enabled(language) {
            continue;
        }
        let case = &row.malformed;
        let tree = parse(case.source.as_bytes(), language)
            .unwrap_or_else(|| panic!("{language:?} recovers a tree"));
        assert!(
            tree.root_node().has_error(),
            "{language:?} source is malformed"
        );
        assert_eq!(
            first_text_of_kind(&tree, case.declaration_kind, case.source.as_bytes()),
            Some(case.declaration_text),
            "{language:?} recovery keeps the whole recognized declaration"
        );
        assert_eq!(
            enclosing_unit(
                case.source,
                language,
                point_of(case.source, case.probe).into()
            ),
            None,
            "{language:?} extraction rejects an error tree"
        );
        proved += 1;
    }
    assert_covered(proved, tree_sitter_languages(), SUBJECT);
}

#[test]
fn unsupported_nodes_return_none() {
    let mut proved = 0_usize;
    for row in &CASES {
        let language = row.language;
        if !extraction_enabled(language) {
            continue;
        }
        let case = &row.unsupported;
        let tree = parse(case.source.as_bytes(), language)
            .unwrap_or_else(|| panic!("{language:?} parses"));
        assert!(
            !tree.root_node().has_error(),
            "{language:?} source is clean"
        );
        assert_eq!(
            enclosing_unit(
                case.source,
                language,
                point_of(case.source, case.probe).into()
            ),
            None,
            "{language:?} recognizes no declaration here"
        );
        proved += 1;
    }
    assert_covered(proved, tree_sitter_languages(), SUBJECT);
}
