//! What one bounded Go fact inventory states as the type evidence a resolver
//! reads.
//!
//! A submodule of `tests/enclosing_unit.rs`, reached through a `#[path]`
//! attribute. It shares [`go_fact_source`](crate::go_fact_source)'s fixture
//! with the completeness case, because the types a source writes are only
//! meaningful beside the declarations and bindings that same inventory states.
//!
//! Every table here is written over every binding or every declaration rather
//! than over the ones that carry the evidence, so a walk that started guessing
//! a type where the grammar proves none fails as loudly as one that stopped
//! stating the type it does prove.

use pedant_syntax::go::{
    GoBindingFact, GoDeclarationFact, GoDeclarationKind, GoFileFacts, GoInitializerForm,
    GoSignatureRole, GoSignatureTermFact,
};

use crate::go_fact_source::complete_facts;

/// What every bound name's initializer states, in binding order.
///
/// A short variable declaration writes no type, so the initializer is the whole
/// evidence of what it binds. A map, a slice, a channel conversion, an address
/// taken of a call, and a declaration distributing results across several names
/// state none.
const INITIALIZERS: &[&str] = &[
    "n|none",
    "count|none",
    "sum|none",
    "local|none",
    "inner|none",
    "c|none",
    "n|none",
    "label|none",
    "raw|none",
    "value|literal|-|Config|false",
    "pointed|literal-address|-|Config|true",
    "foreign|literal|alias|Client|false",
    "called|call|-|build|false",
    "remote|call|alias|Get|false",
    "converted|call|-|Handle|false",
    "mapped|none",
    "sliced|none",
    "piped|none",
    "taken|none",
    "first|none",
    "second|none",
    "blocked|none",
    "client|none",
    "held|none",
    "linked|none",
    "n|none",
    "picked|none",
    "picked|none",
    "format|none",
    "args|none",
];

/// What every bound name's own declaration writes as its type, in binding order.
///
/// A receiver, a parameter, a named result, and a `var` inside a body all write
/// their type, and the package that type belongs to is written beside it. A walk
/// that folded `alias.Client` into `Client` fails here as loudly as one that
/// stopped stating the type at all: the qualifier is what decides which package
/// a receiver's method set is read from, and `Client` and `Config` are both
/// names this file can see bare.
const DECLARED_TYPES: &[&str] = &[
    "n|-|int|false",
    "count|-|int|false",
    "sum|-|int|false",
    "local|-|-|false",
    "inner|-|int|false",
    "c|-|Config|true",
    "n|-|int|false",
    "label|-|-|false",
    "raw|-|int|false",
    "value|-|-|false",
    "pointed|-|-|false",
    "foreign|-|-|false",
    "called|-|-|false",
    "remote|-|-|false",
    "converted|-|-|false",
    "mapped|-|-|false",
    "sliced|-|-|false",
    "piped|-|-|false",
    "taken|-|-|false",
    "first|-|-|false",
    "second|-|-|false",
    "blocked|-|-|false",
    "client|alias|Client|false",
    "held|-|Config|false",
    "linked|alias|Client|true",
    "n|-|int|false",
    "picked|-|-|false",
    "picked|-|-|false",
    "format|-|string|false",
    "args|-|any|false",
];

/// What every declaration states as the single type its callable returns, in
/// declaration order.
///
/// A call's value carries a type only when the source writes exactly one. A
/// declaration that is no callable, a callable stating no result, several
/// results, an unnamed composite, and a pointer wrapping a shape the model names
/// no type for all state none here.
///
/// `build` is the row that keeps the parenthesized form from being dropped.
/// `(sum int)` is the normal spelling of a named result, and the grammar writes
/// it as a parameter list holding one declaration — a reader that stopped at the
/// list would name no type for the most ordinary single-result signature in Go.
const DECLARED_RESULTS: &[&str] = &[
    "Limit|-|-|false",
    "Shared|-|-|false",
    "Config|-|-|false",
    "Retries|-|-|false",
    "Stringer|-|-|false",
    "Runner|-|-|false",
    "Run|-|error|false",
    "Handle|-|-|false",
    "Alias|-|-|false",
    "build|-|int|false",
    "Run|-|error|false",
    "shapes|-|-|false",
    "spawn|-|Config|true",
    "fetch|alias|Client|false",
    "pair|-|-|false",
    "table|-|-|false",
    "boxed|-|-|true",
    "serve|-|-|false",
    "Embedder|-|-|false",
    "Config|-|-|false",
    "Handle|-|-|false",
    "classify|-|-|false",
    "Sink|-|-|false",
    "Write|-|error|false",
    "Close|-|error|false",
    "logf|-|-|false",
];

/// What every embedded declaration writes as its type.
///
/// The package qualifier is part of the identity. Retaining only `Stringer`
/// would let a consumer silently substitute a same-named local type for
/// `fmt.Stringer`, so the qualified row is written beside a bare one: a walk
/// that hardcoded a qualifier and one that dropped every qualifier each fail
/// against one of the two.
///
/// `*Handle` is the pointer form, and it is the row that keeps the walk from
/// stopping at the `pointer_type` wrapper: the name is read from inside the
/// wrapper, and the form the source wrote is stated beside it rather than
/// folded into the name.
const EMBEDDED_TYPES: &[&str] = &[
    "Stringer|fmt|Stringer|false",
    "Config|-|Config|false",
    "Handle|-|Handle|true",
];

/// Every term every callable's signature states, in declaration order and, for
/// each callable, parameters before results.
///
/// A method set is compared term by term, so each half of a term is a claim of
/// its own: the role says which list wrote it, the position says where in that
/// list, the qualifier and name say which type, and the variadic flag says the
/// term absorbs the rest of the call.
///
/// Arity is what the terms exist for. `Write([]byte) error` binds no name at
/// all, so a reader of bindings alone cannot tell it from `Close() error`; the
/// two rows below differ by exactly one parameter term. `logf` states the
/// variadic tail, and `table` and `boxed` state terms whose shape names no
/// single type — a gap this model reports rather than guesses at.
const SIGNATURE_TERMS: &[&str] = &[
    "Run|parameter|0|-|int|false|false",
    "Run|result|0|-|error|false|false",
    "build|parameter|0|-|int|false|false",
    "build|result|0|-|int|false|false",
    "Run|parameter|0|-|int|false|false",
    "Run|result|0|-|error|false|false",
    "shapes|parameter|0|-|int|false|false",
    "spawn|result|0|-|Config|true|false",
    "fetch|result|0|alias|Client|false|false",
    "pair|result|0|-|int|false|false",
    "pair|result|1|-|error|false|false",
    "table|result|0|-|-|false|false",
    "boxed|result|0|-|-|true|false",
    "serve|parameter|0|alias|Client|false|false",
    "classify|parameter|0|-|int|false|false",
    "Write|parameter|0|-|-|false|false",
    "Write|result|0|-|error|false|false",
    "Close|result|0|-|error|false|false",
    "logf|parameter|0|-|string|false|false",
    "logf|parameter|1|-|any|false|true",
];

/// 7.T2 (Invariants 1-3): one bounded inventory states the written type, the
/// initializer, and the declared result of every name Step 7 resolves.
#[test]
fn go_file_facts_state_every_written_type_and_initializer() {
    let facts = complete_facts();

    assert_initializers(&facts);
    assert_declared_types(&facts);
    assert_declared_results(&facts);
    assert_embedded_types(&facts);
    assert_signature_terms(&facts);
}

/// Every signature term, compared as one ordered list.
fn assert_signature_terms(facts: &GoFileFacts<'_>) {
    let stated: Box<[String]> = facts
        .signature_terms()
        .iter()
        .map(|term| signature_row(facts, term))
        .collect();
    let borrowed: Box<[&str]> = stated.iter().map(String::as_str).collect();
    assert_eq!(
        &*borrowed, SIGNATURE_TERMS,
        "a signature states one term per type its source writes, in the order it writes them"
    );
}

/// One signature term as this module compares it: the callable that states it,
/// the role, the position, then the qualifier, the name, the pointer form, and
/// the variadic form of the type written there.
fn signature_row(facts: &GoFileFacts<'_>, term: &GoSignatureTermFact<'_>) -> String {
    let declared = facts
        .declarations()
        .get(term.declaration() as usize)
        .expect("every term names a declaration the inventory states");
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        declared.name(),
        role_name(term.role()),
        term.position(),
        term.type_qualifier().unwrap_or("-"),
        term.type_name().unwrap_or("-"),
        term.pointer(),
        term.variadic()
    )
}

/// The spelling one signature role is written down as.
///
/// Spelled out rather than derived from `Debug`, so a third role is a table
/// this module must revise rather than a row whose text changes under it.
fn role_name(role: GoSignatureRole) -> &'static str {
    match role {
        GoSignatureRole::Parameter => "parameter",
        GoSignatureRole::Result => "result",
    }
}

/// Every binding's initializer evidence, compared as one ordered list.
fn assert_initializers(facts: &GoFileFacts<'_>) {
    let stated: Box<[String]> = facts.bindings().iter().map(initializer_row).collect();
    let borrowed: Box<[&str]> = stated.iter().map(String::as_str).collect();
    assert_eq!(
        &*borrowed, INITIALIZERS,
        "an initializer states the type its shape names, and nothing where its shape names none"
    );
}

/// One binding's initializer as this module compares it: the bound name, the
/// form, the qualifier and name it states, and whether it is a pointer.
fn initializer_row(bound: &GoBindingFact<'_>) -> String {
    let Some(stated) = bound.initializer() else {
        return format!("{}|none", bound.name());
    };
    format!(
        "{}|{}|{}|{}|{}",
        bound.name(),
        form_name(stated.form()),
        stated.qualifier().unwrap_or("-"),
        stated.name(),
        stated.pointer()
    )
}

/// The spelling one initializer form is written down as.
///
/// Spelled out rather than derived from `Debug`, so a form added to the closed
/// set is a table this module must revise rather than a row whose text changes
/// under it.
fn form_name(form: GoInitializerForm) -> &'static str {
    match form {
        GoInitializerForm::CompositeLiteral => "literal",
        GoInitializerForm::CompositeLiteralAddress => "literal-address",
        GoInitializerForm::Call => "call",
    }
}

/// Every binding's written type, compared as one ordered list.
fn assert_declared_types(facts: &GoFileFacts<'_>) {
    let stated: Box<[String]> = facts.bindings().iter().map(declared_type_row).collect();
    let borrowed: Box<[&str]> = stated.iter().map(String::as_str).collect();
    assert_eq!(
        &*borrowed, DECLARED_TYPES,
        "a binding states the type its declaration writes, with the package that type names"
    );
}

/// One binding's written type as this module compares it: the bound name, then
/// the qualifier, the name, and the pointer form of the type it writes.
fn declared_type_row(bound: &GoBindingFact<'_>) -> String {
    format!(
        "{}|{}|{}|{}",
        bound.name(),
        bound.type_qualifier().unwrap_or("-"),
        bound.type_name().unwrap_or("-"),
        bound.pointer()
    )
}

/// Every declaration's declared result, compared as one ordered list.
fn assert_declared_results(facts: &GoFileFacts<'_>) {
    let stated: Box<[String]> = facts.declarations().iter().map(result_row).collect();
    let borrowed: Box<[&str]> = stated.iter().map(String::as_str).collect();
    assert_eq!(
        &*borrowed, DECLARED_RESULTS,
        "a declaration states the single result type its source writes, and none where it writes no single type"
    );
}

/// One declaration's result as this module compares it: the declared name, then
/// the qualifier, the name, and the pointer form of the result it states.
///
/// The pointer form is rendered even where the result names no type, because it
/// is read off the source rather than derived from the name: `*[]Config` states
/// a pointer to a shape the model names no single type for.
fn result_row(declared: &GoDeclarationFact<'_>) -> String {
    format!(
        "{}|{}|{}|{}",
        declared.name(),
        declared.result_qualifier().unwrap_or("-"),
        declared.result_name().unwrap_or("-"),
        declared.result_pointer()
    )
}

/// Every embedded declaration's written type, compared as one ordered list.
fn assert_embedded_types(facts: &GoFileFacts<'_>) {
    let stated: Box<[String]> = facts
        .declarations()
        .iter()
        .filter(|declared| declared.kind() == GoDeclarationKind::EmbeddedField)
        .map(embedded_type_row)
        .collect();
    let borrowed: Box<[&str]> = stated.iter().map(String::as_str).collect();
    assert_eq!(
        &*borrowed, EMBEDDED_TYPES,
        "an embedded declaration retains the package-qualified type its source writes"
    );
}

/// One embedded declaration's name and complete written type.
fn embedded_type_row(declared: &GoDeclarationFact<'_>) -> String {
    format!(
        "{}|{}|{}|{}",
        declared.name(),
        declared.embedded_qualifier().unwrap_or("-"),
        declared.embedded_name().unwrap_or("-"),
        declared.embedded_pointer()
    )
}
