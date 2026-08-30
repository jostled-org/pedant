//! The wire shape of every answer this product sends, written down.
//!
//! Every other CLI expectation in these journeys is the library's own answer to
//! the same question, serialized by the same serializer the binary under test
//! runs. That comparison states one true thing — the binary is a transport over
//! the library and adds nothing — and it cannot state anything about the bytes:
//! a renamed serde field renames it on both sides at once and every row still
//! agrees. So no expectation anywhere in this root was a claim about the wire,
//! which is the one surface a client outside this repository reads.
//!
//! These documents are that claim. Each names, for one response type, the
//! fields the envelope and its answer carry and the JSON kind each field takes.
//! They are written here by hand, from the contract rather than from a run, for
//! the reason [`crate::queries::expectations`] writes its structure rows down: an
//! expectation taken from the subject agrees with whatever the subject became.
//!
//! What a shape does not state is how much a row holds. Emptiness is a fact
//! about a fixture rather than about a wire format, and it already has an owner
//! in [`crate::journeys::outcome::assert_states_something`] — so an array shape
//! here says what every row of that array must look like and nothing about how
//! many there are.

use serde_json::{Map, Value, json};

/// The suffix marking a field the wire may omit.
///
/// A field with `skip_serializing_if` is absent rather than null when the answer
/// does not state it, so a shape that required it would fail on the answers that
/// are right. Present is still checked: an optional field that appears is held
/// to its shape like every other.
const OPTIONAL: char = '?';

/// The prefix marking a written-down value rather than a JSON kind.
const LITERAL: char = '=';

/// One revision-bound identity, as every answer spells one.
fn handle() -> Value {
    json!({ "revision": "string", "id": "number" })
}

/// What every envelope says about the state it was answered from.
fn health() -> Value {
    json!({ "status": "string", "issues": "number", "stale_scopes": "number" })
}

/// The extent one structure covers, in bytes and in lines.
fn span() -> Value {
    json!({
        "start_byte": "number",
        "end_byte": "number",
        "start_line": "number",
        "end_line": "number"
    })
}

/// What every navigation answer says about one structure.
fn descriptor() -> Value {
    json!({
        "handle": handle(),
        "owner": "object|null",
        "language": "string",
        "kind": "string",
        "name": "string|null",
        "qualified_name": "string",
        "path": "string",
        "span": span(),
        "coverage": "string",
        "projects": "array"
    })
}

/// One structure and the exact source its span covers.
fn structure_source() -> Value {
    json!({ "structure": descriptor(), "text": "string" })
}

/// One refusal, as a client branches on it.
///
/// Two fields every refusal states and eight it states only where it qualifies
/// itself: a capacity refusal carries its four numbers and a stale handle
/// carries none.
fn error() -> Value {
    json!({
        "code": "string",
        "message": "string",
        "path?": "string",
        "project?": "string",
        "stage?": "string",
        "coverage?": "string",
        "owner?": "string",
        "collection?": "string",
        "observed?": "number",
        "limit?": "number"
    })
}

/// The envelope every answer travels in, around one result shape.
fn envelope(result: Value) -> Value {
    json!({
        "index_revision": "string",
        "state_revision": "string",
        "health": health(),
        "result": result,
        "next_page?": "string"
    })
}

/// What `list-projects` and `list_projects` send.
pub fn projects() -> Value {
    envelope(json!([{
        "handle": handle(),
        "language": "string",
        "authority": "string",
        "unit": "string",
        "coverage": "string",
        "health": health()
    }]))
}

/// What `search` and `search_symbols` send.
pub fn symbols() -> Value {
    envelope(json!([descriptor()]))
}

/// What `outline` and `outline_file` send.
pub fn outline() -> Value {
    envelope(json!({
        "path": "string",
        "language": "string",
        "structures": [descriptor()]
    }))
}

/// What `read` and `read_structure` send.
pub fn source() -> Value {
    envelope(structure_source())
}

/// What `at` and `structure_at` send.
///
/// The same result shape as [`source`], and written as its own row rather than
/// as a second name for it: two operations that happen to answer alike today
/// are two contracts, and a shared row would let one of them move without a
/// reader noticing which.
pub fn point() -> Value {
    envelope(structure_source())
}

/// What `relations` and `query_relations` send.
pub fn relations() -> Value {
    envelope(json!([{
        "project": handle(),
        "seed": "number",
        "coverage": "string",
        "neighbors": "array",
        "nodes": "array",
        "edges": "array",
        "containment": "array",
        "unresolved": "array"
    }]))
}

/// What `path` and `find_path` send.
///
/// The selected route is absent rather than null where no eligible pair is
/// connected, so a client reads "no route" from the missing field.
pub fn path() -> Value {
    envelope(json!({
        "selected?": {
            "project": handle(),
            "nodes": "array",
            "edges": "array"
        }
    }))
}

/// What `graph components` and `analyze_graph` in that mode send.
///
/// The mode is pinned as the word itself. It is the tag of an adjacently tagged
/// enum, so it is the one field that says which of five answers the `answer`
/// field holds, and a shape that admitted any string would admit an answer of
/// the wrong kind.
pub fn components() -> Value {
    envelope(json!({
        "mode": "=components",
        "answer": [{ "id": "number", "members": "array", "cyclic": "boolean" }]
    }))
}

/// What `graph degree_centrality` sends.
pub fn degree_centrality() -> Value {
    envelope(json!({
        "mode": "=degree_centrality",
        "answer": [{ "entity": "object", "incoming": "number", "outgoing": "number" }]
    }))
}

/// What a query that ran and refused sends.
///
/// The revisions and the health are the ones a successful answer carries: a
/// client deciding whether to retry has to know whether the index moved.
pub fn refusal() -> Value {
    json!({
        "index_revision": "string",
        "state_revision": "string",
        "health": health(),
        "error": error()
    })
}

/// What a build that produced no state sends.
///
/// No revisions and no health, because there is no state to take them from.
pub fn fatal_refusal() -> Value {
    json!({ "error": error() })
}

/// One answer states exactly the fields the shape written down for it names.
///
/// The whole document is compared before anything is reported, and every
/// departure is named, so one run says which fields moved rather than the first
/// one a walk happened to reach.
pub fn assert_states_shape(answer: &str, shape: &Value, claim: &str) {
    let stated: Value = serde_json::from_str(answer)
        .unwrap_or_else(|error| panic!("{claim}: the answer is one JSON document: {error}"));
    let faults = departures(&stated, shape, "");
    assert!(
        faults.is_empty(),
        "{claim}: the answer states the shape written down for it: {faults:?}: {answer}"
    );
}

/// Every way one answer departs from the shape written down for it.
///
/// The list is a `Vec` because every level extends it with the level below;
/// each fault in it is a `Box<str>`, written once at the point the departure was
/// found and read only by the message that reports them all.
fn departures(subject: &Value, shape: &Value, at: &str) -> Vec<Box<str>> {
    match shape {
        Value::Object(fields) => object_departures(subject, fields, at),
        Value::Array(element) => array_departures(subject, element, at),
        Value::String(kinds) => kind_departures(subject, kinds, at),
        _ => vec![format!("{at}: {shape} is not a shape this table can state").into()],
    }
}

/// Every departure of one object from the fields named for it.
fn object_departures(subject: &Value, fields: &Map<String, Value>, at: &str) -> Vec<Box<str>> {
    let Some(stated) = subject.as_object() else {
        return vec![format!("{at}: names an object, and the answer states {subject}").into()];
    };
    let mut found = named_departures(stated, fields, at);
    for (key, shape) in fields {
        let field = key.trim_end_matches(OPTIONAL);
        found.extend(
            stated
                .get(field)
                .map(|held| departures(held, shape, &format!("{at}/{field}")))
                .unwrap_or_default(),
        );
    }
    found
}

/// Every field the answer owes and every field it states beside them.
fn named_departures(
    stated: &Map<String, Value>,
    fields: &Map<String, Value>,
    at: &str,
) -> Vec<Box<str>> {
    let named: Vec<&str> = fields
        .keys()
        .map(|key| key.trim_end_matches(OPTIONAL))
        .collect();
    let mut found: Vec<Box<str>> = fields
        .keys()
        .filter(|key| !key.ends_with(OPTIONAL) && !stated.contains_key(key.as_str()))
        .map(|key| format!("{at}/{key}: the answer states no such field").into())
        .collect();
    found.extend(
        stated
            .keys()
            .filter(|key| !named.contains(&key.as_str()))
            .map(|key| {
                Box::from(format!(
                    "{at}/{key}: this product's wire shape names no such field"
                ))
            }),
    );
    found
}

/// Every departure of one array's rows from the row shape named for it.
///
/// The count is nobody's claim here. An array shape states what a row looks
/// like, and a table with no rows says nothing about the wire format either way.
fn array_departures(subject: &Value, element: &[Value], at: &str) -> Vec<Box<str>> {
    let Some(rows) = subject.as_array() else {
        return vec![format!("{at}: names an array, and the answer states {subject}").into()];
    };
    let Some(shape) = element.first() else {
        return vec![format!("{at}: the shape document names no row").into()];
    };
    rows.iter()
        .enumerate()
        .flat_map(|(index, row)| departures(row, shape, &format!("{at}/{index}")))
        .collect()
}

/// Every departure of one leaf from the kinds, or the value, named for it.
fn kind_departures(subject: &Value, kinds: &str, at: &str) -> Vec<Box<str>> {
    match kinds.split('|').any(|kind| states(subject, kind)) {
        true => Vec::new(),
        false => vec![format!("{at}: names {kinds}, and the answer states {subject}").into()],
    }
}

/// Whether one value is what a single kind token names.
fn states(subject: &Value, kind: &str) -> bool {
    match (kind, subject) {
        ("any", _) => true,
        ("string", Value::String(_)) => true,
        ("number", Value::Number(_)) => true,
        ("boolean", Value::Bool(_)) => true,
        ("null", Value::Null) => true,
        ("array", Value::Array(_)) => true,
        ("object", Value::Object(_)) => true,
        (written, Value::String(held)) => written
            .strip_prefix(LITERAL)
            .is_some_and(|word| word == held),
        _ => false,
    }
}
