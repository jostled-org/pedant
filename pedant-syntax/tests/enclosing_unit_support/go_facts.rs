//! What one bounded Go fact inventory states about the source it was built
//! from.
//!
//! A submodule of `tests/enclosing_unit.rs`, reached through a `#[path]`
//! attribute. [`go_fact_source`](crate::go_fact_source)'s one source carries
//! every grammar shape the inventory claims, so the ordering, the spans, the
//! scopes, the bindings, the conditions, and the anchors are all read off the
//! same bytes rather than off a fixture per claim. What that source writes as
//! the type of each name it binds is read beside them, in
//! [`go_type_facts`](crate::go_type_facts).
//!
//! Every span assertion resolves back through the source: a fact's byte range
//! slices the exact text it names, so a span that drifts fails here rather than
//! travelling into a resolution report.

use pedant_syntax::go::{
    GoBindingKind, GoBuildConditionKind, GoDeclarationKind, GoFactLimits, GoFactSpan, GoFileFacts,
    GoImportForm, GoReferenceKind, GoScopeKind,
};
use pedant_syntax::tree_sitter::SourceUnitAnchor;
use pedant_syntax::{Location, SourceUnitKind};

use crate::go_fact_source::{FACT_SOURCE, complete_facts, facts};

/// One import as this module compares it: form, path, alias, bound name, and
/// the line it opens on.
type ImportRow<'a> = (
    GoImportForm,
    &'a str,
    Option<&'a str>,
    Option<&'a str>,
    usize,
);

/// The exact text one span names.
///
/// Every span this crate publishes indexes the source it was extracted from, so
/// slicing is the check: a span that drifts by a byte returns other text, and a
/// span that leaves the source panics here instead of being reported as a fact.
fn text_of(source: &str, span: GoFactSpan) -> &str {
    source
        .get(span.byte_range())
        .unwrap_or_else(|| panic!("{span:?} must slice the source it was extracted from"))
}

/// Assert one span opens where the source's own line and column say it does.
fn assert_span_position(source: &str, span: GoFactSpan, line: usize, column: usize) {
    assert_eq!(
        (span.start_line(), span.start_column()),
        (line, column),
        "{:?} opens at line {line} column {column}",
        text_of(source, span)
    );
    let opened = source
        .lines()
        .nth(line)
        .unwrap_or_else(|| panic!("the source holds line {line}"));
    assert!(
        opened.len() >= column,
        "line {line} holds column {column}, got {opened:?}"
    );
}

/// 2.T1 (Invariants 1-3): one bounded inventory states every Go grammar fact in
/// source order, bound to the exact bytes it was extracted from.
#[test]
fn go_file_facts_are_complete_ordered_and_source_bound() {
    let facts = complete_facts();

    assert_package_and_conditions(&facts);
    assert_imports(&facts);
    assert_declarations(&facts);
    assert_references(&facts);
    assert_scopes_and_bindings(&facts);
    assert_switch_clause_scopes(&facts);
    assert_anchors(&facts);
    assert_recovery_and_language_are_exact();
}

/// The package clause and the build predicates that precede it.
fn assert_package_and_conditions(facts: &GoFileFacts<'_>) {
    assert_eq!(facts.package_name(), Some("widget"));
    let clause = facts.package_span().expect("a package clause span");
    assert_eq!(text_of(FACT_SOURCE, clause), "widget");
    assert_span_position(FACT_SOURCE, clause, 3, 8);

    let stated: Box<[(GoBuildConditionKind, &str, usize)]> = facts
        .build_conditions()
        .iter()
        .map(|condition| {
            (
                condition.kind(),
                condition.constraint(),
                condition.span().start_line(),
            )
        })
        .collect();
    assert_eq!(
        &*stated,
        &[
            (GoBuildConditionKind::GoBuild, "linux && cgo", 0),
            (GoBuildConditionKind::LegacyBuildTag, "linux,cgo", 1),
        ],
        "both build predicates are retained verbatim, in source order"
    );
}

/// Every import form the file states, with the name each binds.
fn assert_imports(facts: &GoFileFacts<'_>) {
    let stated: Box<[ImportRow<'_>]> = facts
        .imports()
        .iter()
        .map(|import| {
            (
                import.form(),
                import.path(),
                import.alias(),
                import.local_name(),
                import.span().start_line(),
            )
        })
        .collect();
    assert_eq!(
        &*stated,
        &[
            (GoImportForm::Named, "fmt", None, Some("fmt"), 6),
            (
                GoImportForm::Aliased,
                "net/http",
                Some("alias"),
                Some("alias"),
                7
            ),
            (GoImportForm::Blank, "embed", None, None, 8),
            (GoImportForm::Dot, "strings", None, None, 9),
        ],
        "imports keep source order, exact spelling, and the name each binds"
    );

    for import in facts.imports() {
        assert!(
            text_of(FACT_SOURCE, import.span()).contains(import.path()),
            "an import's span holds the path it names"
        );
    }
}

/// Every declaration the file states, in source order, with its owner.
fn assert_declarations(facts: &GoFileFacts<'_>) {
    let stated: Box<[(GoDeclarationKind, &str)]> = facts
        .declarations()
        .iter()
        .map(|declaration| (declaration.kind(), declaration.name()))
        .collect();
    assert_eq!(
        &*stated,
        &[
            (GoDeclarationKind::Constant, "Limit"),
            (GoDeclarationKind::Variable, "Shared"),
            (GoDeclarationKind::Struct, "Config"),
            (GoDeclarationKind::Field, "Retries"),
            (GoDeclarationKind::EmbeddedField, "Stringer"),
            (GoDeclarationKind::Interface, "Runner"),
            (GoDeclarationKind::InterfaceMethod, "Run"),
            (GoDeclarationKind::DefinedType, "Handle"),
            (GoDeclarationKind::TypeAlias, "Alias"),
            (GoDeclarationKind::Function, "build"),
            (GoDeclarationKind::Method, "Run"),
            (GoDeclarationKind::Function, "shapes"),
            (GoDeclarationKind::Function, "spawn"),
            (GoDeclarationKind::Function, "fetch"),
            (GoDeclarationKind::Function, "pair"),
            (GoDeclarationKind::Function, "table"),
            (GoDeclarationKind::Function, "boxed"),
            (GoDeclarationKind::Function, "serve"),
            (GoDeclarationKind::Struct, "Embedder"),
            (GoDeclarationKind::EmbeddedField, "Config"),
            (GoDeclarationKind::EmbeddedField, "Handle"),
            (GoDeclarationKind::Function, "classify"),
            (GoDeclarationKind::Interface, "Sink"),
            (GoDeclarationKind::InterfaceMethod, "Write"),
            (GoDeclarationKind::InterfaceMethod, "Close"),
            (GoDeclarationKind::Function, "logf"),
        ],
        "declarations keep source order and their declared spelling"
    );

    for declaration in facts.declarations() {
        assert_eq!(
            text_of(FACT_SOURCE, declaration.name_span()),
            declaration.name(),
            "a declaration's name span slices its own name"
        );
    }

    assert_declaration_owners(facts);
}

/// A member declaration names the declaration that holds it; a package-level
/// one names none.
fn assert_declaration_owners(facts: &GoFileFacts<'_>) {
    let owner = |name: &str, kind: GoDeclarationKind| -> Option<&str> {
        let held = facts
            .declarations()
            .iter()
            .find(|declaration| declaration.name() == name && declaration.kind() == kind)
            .unwrap_or_else(|| panic!("{name} is declared"));
        held.parent()
            .map(|index| facts.declarations()[index as usize].name())
    };

    assert_eq!(owner("Retries", GoDeclarationKind::Field), Some("Config"));
    assert_eq!(
        owner("Stringer", GoDeclarationKind::EmbeddedField),
        Some("Config")
    );
    assert_eq!(
        owner("Run", GoDeclarationKind::InterfaceMethod),
        Some("Runner")
    );
    assert_eq!(owner("Config", GoDeclarationKind::Struct), None);
    assert_eq!(owner("build", GoDeclarationKind::Function), None);
    assert_eq!(owner("Run", GoDeclarationKind::Method), None);

    let method = facts
        .declarations()
        .iter()
        .find(|declaration| declaration.kind() == GoDeclarationKind::Method)
        .expect("the method declaration");
    let receiver = method.receiver().expect("a method states its receiver");
    let receiver = &facts.bindings()[receiver as usize];
    assert_eq!(receiver.kind(), GoBindingKind::Receiver);
    assert_eq!(receiver.name(), "c");
    assert_eq!(receiver.type_name(), Some("Config"));
    assert!(
        receiver.pointer(),
        "the receiver is written in pointer form"
    );
}

/// Reference sites carry the call, selector, type, and value shapes resolution
/// reads, each inside the declaration that states it.
fn assert_references(facts: &GoFileFacts<'_>) {
    let named = |kind: GoReferenceKind, qualifier: Option<&str>, name: &str| {
        facts
            .references()
            .iter()
            .find(|reference| {
                reference.kind() == kind
                    && reference.qualifier() == qualifier
                    && reference.name() == name
            })
            .unwrap_or_else(|| panic!("{kind:?} {qualifier:?}.{name} is stated"))
    };

    let println = named(GoReferenceKind::QualifiedCall, Some("fmt"), "Println");
    assert_span_position(FACT_SOURCE, println.span(), 35, 1);
    assert_eq!(text_of(FACT_SOURCE, println.span()), "fmt.Println(sum)");
    let owner = println
        .declaration()
        .expect("a call inside a function names it");
    assert_eq!(facts.declarations()[owner as usize].name(), "build");

    let config = named(GoReferenceKind::Type, None, "Config");
    assert_eq!(text_of(FACT_SOURCE, config.name_span()), "Config");

    let embedded = named(GoReferenceKind::Type, Some("fmt"), "Stringer");
    assert_span_position(FACT_SOURCE, embedded.span(), 18, 1);

    let value = named(GoReferenceKind::Value, None, "local");
    assert!(
        value.span().start_line() >= 32,
        "the first `local` value reference sits after its binding"
    );

    assert!(
        facts
            .references()
            .iter()
            .all(|reference| !text_of(FACT_SOURCE, reference.name_span()).is_empty()),
        "every reference names bytes the source holds"
    );

    let lines: Box<[usize]> = facts
        .references()
        .iter()
        .map(|reference| reference.span().start_line())
        .collect();
    let mut sorted = lines.clone();
    sorted.sort_unstable();
    assert_eq!(lines, sorted, "references keep source order");
}

/// Lexical scopes nest, and every binding names the scope it is visible in.
fn assert_scopes_and_bindings(facts: &GoFileFacts<'_>) {
    let file = facts.scopes().first().expect("a file scope");
    assert_eq!(file.kind(), GoScopeKind::File);
    assert_eq!(file.parent(), None);
    assert_eq!(text_of(FACT_SOURCE, file.span()).len(), FACT_SOURCE.len());

    assert!(
        facts
            .scopes()
            .iter()
            .skip(1)
            .all(|scope| scope.parent().is_some()),
        "every scope but the file scope names its parent"
    );

    let binding = |name: &str| {
        facts
            .bindings()
            .iter()
            .find(|binding| binding.name() == name)
            .unwrap_or_else(|| panic!("{name} is bound"))
    };

    assert_eq!(binding("count").kind(), GoBindingKind::Parameter);
    assert_eq!(binding("sum").kind(), GoBindingKind::Result);
    assert_eq!(binding("local").kind(), GoBindingKind::Local);
    assert_eq!(binding("inner").kind(), GoBindingKind::Variable);
    assert_eq!(binding("c").kind(), GoBindingKind::Receiver);

    let inner = binding("inner");
    let block = &facts.scopes()[inner.scope() as usize];
    assert_eq!(
        block.kind(),
        GoScopeKind::Block,
        "a `var` inside a nested block binds in that block"
    );
    let holder = block.parent().expect("the block sits inside the function");
    assert_eq!(facts.scopes()[holder as usize].kind(), GoScopeKind::Block);

    assert_eq!(
        facts.declarations()[binding("count")
            .declaration()
            .expect("a parameter names its declaration") as usize]
            .name(),
        "build"
    );
}

/// Each clause of a `switch` binds into a scope of its own.
///
/// The Go specification makes every clause an implicit block. A resolver picks
/// the innermost binding whose scope opens before the occurrence, so two
/// clauses sharing one scope let `case 1`'s `picked` answer for `case 2`'s
/// read — a wrong answer rather than a withheld one. The fixture binds one name
/// in each clause, so the claim is that the two scopes differ and that neither
/// holds the other.
fn assert_switch_clause_scopes(facts: &GoFileFacts<'_>) {
    let clauses: Box<[u32]> = facts
        .bindings()
        .iter()
        .filter(|bound| bound.name() == "picked")
        .map(|bound| bound.scope())
        .collect();
    assert_eq!(
        clauses.len(),
        2,
        "both `case` clauses bind a name the walk states"
    );
    assert_ne!(
        clauses[0], clauses[1],
        "each `case` clause opens a scope of its own"
    );
    for held in clauses.iter().copied() {
        assert_eq!(
            facts.scopes()[held as usize].kind(),
            GoScopeKind::Block,
            "a clause scope is a block"
        );
    }
    assert!(
        !encloses(facts, clauses[0], clauses[1]) && !encloses(facts, clauses[1], clauses[0]),
        "neither clause scope holds the other, so no sibling binding is in view"
    );
}

/// Whether `outer` is `inner` or holds it, through the parent chain.
fn encloses(facts: &GoFileFacts<'_>, outer: u32, inner: u32) -> bool {
    let mut held = Some(inner);
    while let Some(index) = held {
        match index == outer {
            true => return true,
            false => held = facts.scopes()[index as usize].parent(),
        }
    }
    false
}

/// The inventory is the sole Go declaration index, so it answers the same
/// enclosing-unit question the public extraction API does.
fn assert_anchors(facts: &GoFileFacts<'_>) {
    let anchors = facts.enclosing_unit_anchors(&[
        Location {
            line: 36,
            column: Some(2),
        },
        Location {
            line: 41,
            column: Some(2),
        },
        Location {
            line: 18,
            column: Some(2),
        },
        Location {
            line: 23,
            column: Some(2),
        },
        Location {
            line: 4,
            column: Some(1),
        },
    ]);
    let stated: Box<[String]> = anchors.iter().map(render_anchor).collect();
    assert_eq!(
        &*stated,
        &[
            "function build 30:1",
            "method Run 40:1",
            "struct Config 17:1",
            "none",
            "none",
        ],
        "only functions, methods, and struct types anchor a unit"
    );
}

/// One enclosing-unit answer as this module compares it, or `none`.
///
/// Rendered rather than tupled so a failure prints the row a reader can find in
/// the fixture, and so this module states one comparison shape rather than a
/// second one beside the import rows.
fn render_anchor(anchor: &Option<SourceUnitAnchor>) -> String {
    let Some(anchor) = anchor else {
        return String::from("none");
    };
    let column = anchor
        .start
        .column
        .expect("an anchor's start comes from a byte offset, so it carries a column");
    format!(
        "{} {} {}:{column}",
        unit_kind_name(anchor.kind),
        anchor.name.as_deref().unwrap_or("<unnamed>"),
        anchor.start.line
    )
}

/// The spelling one unit kind is written down as.
///
/// The three Go declarations that carry a unit are named; every other kind is a
/// failure this table would have to be revised to accept, so it is spelled out
/// rather than derived from `Debug`.
fn unit_kind_name(kind: SourceUnitKind) -> &'static str {
    match kind {
        SourceUnitKind::Function => "function",
        SourceUnitKind::Method => "method",
        SourceUnitKind::Struct => "struct",
        other => panic!("Go anchors no {other:?} unit"),
    }
}

/// A recovery tree is stated rather than hidden, and a session of another
/// grammar refuses.
fn assert_recovery_and_language_are_exact() {
    assert!(
        !complete_facts().has_errors(),
        "the complete source parses without recovery"
    );

    let broken = "package widget\n\nfunc build( {\n\tlocal := 1\n}\n";
    let recovered =
        facts(broken, GoFactLimits::UNBOUNDED).expect("a recovery tree still states facts");
    assert!(
        recovered.has_errors(),
        "a recovered tree marks its own incompleteness"
    );
    assert_eq!(recovered.package_name(), Some("widget"));

    #[cfg(feature = "ts-python")]
    {
        use pedant_syntax::SyntaxLanguage;
        use pedant_syntax::go::GoFactError;
        use pedant_syntax::tree_sitter::parse_bound;

        let python = parse_bound("def handle():\n    pass\n", SyntaxLanguage::Python)
            .expect("the Python grammar parses");
        assert_eq!(
            python.go_file_facts(GoFactLimits::UNBOUNDED),
            Err(GoFactError::LanguageMismatch {
                language: SyntaxLanguage::Python
            }),
            "a session of another grammar states no Go fact"
        );
    }
}
