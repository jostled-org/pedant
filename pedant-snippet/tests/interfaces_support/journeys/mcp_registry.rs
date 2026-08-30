//! 9.T3: the stdio server exposes exactly the public operations, from one
//! registry.
//!
//! The names, the schemas, and the annotations are written down here rather than
//! read from the server, because a test that derived its expectation from the
//! thing under test would agree with any registry at all. Each annotation is a
//! fact about every one of these tools: it opens source paths, writes nothing,
//! answers the same question the same way, and reaches no host but this one.
//!
//! One claim does read the listing: every property a schema advertises is sent
//! back to the tool that advertised it. That one has no written-down side — the
//! question is whether the server accepts what it publishes, and only the server
//! can say what it publishes.

use serde_json::{Value, json};

use crate::child::Server;
use crate::failure::Failure;
use crate::journeys::client::{self, INVALID_PARAMS};
use crate::journeys::fixture::{Fixture, root_arguments};
use crate::journeys::outcome::assert_clean;

/// Every tool this server serves, in the order a listing states them.
pub(crate) const TOOLS: [&str; 8] = [
    "list_projects",
    "search_symbols",
    "outline_file",
    "read_structure",
    "structure_at",
    "query_relations",
    "find_path",
    "analyze_graph",
];

/// Every behaviour hint each tool publishes, and the value it publishes.
///
/// An absent `annotations` block is not neutral: MCP reads it as
/// `readOnlyHint: false`, `destructiveHint: true`, and `openWorldHint: true`, so
/// a client would gate a question about source text behind an approval prompt.
const ANNOTATIONS: [(&str, bool); 3] = [
    ("readOnlyHint", true),
    ("idempotentHint", true),
    ("openWorldHint", false),
];

/// One tool's required arguments, as its schema must state them.
struct Required {
    /// The tool the row is about.
    tool: &'static str,
    /// Exactly what a call must supply.
    arguments: &'static [&'static str],
}

/// What each schema requires, written down.
static REQUIRED: [Required; 8] = [
    Required {
        tool: "list_projects",
        arguments: &[],
    },
    Required {
        tool: "search_symbols",
        arguments: &["text", "mode"],
    },
    Required {
        tool: "outline_file",
        arguments: &["path"],
    },
    Required {
        tool: "read_structure",
        arguments: &["revision", "structure_id"],
    },
    Required {
        tool: "structure_at",
        arguments: &["path", "line"],
    },
    Required {
        tool: "query_relations",
        arguments: &[
            "revision",
            "structure_id",
            "direction",
            "edge_kinds",
            "certainties",
            "max_depth",
        ],
    },
    Required {
        tool: "find_path",
        arguments: &[
            "from_revision",
            "from_id",
            "to_revision",
            "to_id",
            "edge_kinds",
            "certainties",
        ],
    },
    Required {
        tool: "analyze_graph",
        arguments: &[
            "project_revision",
            "project_id",
            "mode",
            "edge_kinds",
            "certainties",
        ],
    },
];

/// The lowest request id the property probes may use.
///
/// Above every id written down in [`journey`], because a reply is matched to the
/// request that asked for it and a reused id would let one claim read another's
/// answer.
const FIRST_PROBE_ID: i64 = 7;

/// One advertised property, sent alone to the tool that advertises it.
///
/// Both names are `Box<str>`: each is copied out of a listing that is dropped
/// before the assertion phase reads them, and nothing appends to either.
struct Probe {
    /// The tool the property was read off.
    tool: Box<str>,
    /// The property name, exactly as the schema publishes it.
    property: Box<str>,
    /// What the server replied to a call carrying only that property.
    reply: Value,
}

/// Every message this journey exchanged, collected before any assertion.
struct Journey {
    initialize: Value,
    tools: Value,
    probes: Box<[Probe]>,
    unknown_tool: Value,
    misspelled_argument: Value,
    missing_argument: Value,
    wrong_type: Value,
}

#[tokio::test]
async fn code_intelligence_mcp_registry_and_schemas_are_exact() {
    let fixture = Fixture::new();
    let (journey, termination) = client::session(
        &root_arguments(&fixture),
        "the registry journey",
        async |server| journey(server).await,
    )
    .await;

    assert_handshake(&journey.initialize);
    assert_exactly_the_public_operations(&journey.tools);
    assert_every_schema_is_closed(&journey, &REQUIRED);
    assert_every_served_tool_was_probed(&journey);
    assert_every_advertised_property_is_accepted(&journey);
    assert_malformed_calls_stop_before_a_query(&journey);
    assert_clean(&termination, "the registry session");
}

/// Exchange every message, collecting each reply before anything is asserted.
///
/// The listing comes back before the probes, because what is probed is read off
/// the listing itself: the claim is that every property the server advertises is
/// one it accepts, and only the server can say which those are.
async fn journey(server: &mut Server) -> Result<Journey, Failure> {
    let initialize = client::initialized(server).await?;
    let tools = client::listed(server, 2).await?;
    let probes = probed(server, &tools).await?;
    Ok(Journey {
        initialize,
        tools,
        probes,
        unknown_tool: client::called(server, 3, "enclosing_unit", &json!({})).await?,
        misspelled_argument: client::called(server, 4, "outline_file", &json!({"pth": "x"}))
            .await?,
        missing_argument: client::called(server, 5, "outline_file", &json!({})).await?,
        wrong_type: client::called(
            server,
            6,
            "structure_at",
            &json!({"path": "main.go", "line": "four"}),
        )
        .await?,
    })
}

/// Send each advertised property, alone, to the tool that advertises it.
///
/// One property per call rather than a whole argument object. `deny_unknown_fields`
/// reports the first key it cannot name and stops, so a property sent beside
/// others could be masked by an earlier field's own error — and the value sent
/// here is type-valid but otherwise meaningless, so earlier fields would often
/// have one.
///
/// A call carrying one known property still fails: a required argument is
/// missing, or the meaningless value does not parse. Neither is what this probes.
/// What it probes is whether the server can name the key at all.
///
/// Every step here states its failure rather than asserting it, because the
/// whole walk runs while the child is live: a panic between the listing and the
/// teardown unwinds past [`crate::child::Server::shutdown`] and discards the
/// server's own log, which is what a malformed listing most needs explained.
async fn probed(server: &mut Server, listing: &Value) -> Result<Box<[Probe]>, Failure> {
    let mut probes: Vec<Probe> = Vec::new();
    let mut id = FIRST_PROBE_ID;
    for tool in client::tools(listing, "the probed listing")? {
        let name = named(tool)?;
        for (property, shape) in advertised(&tool["inputSchema"], name)? {
            let mut arguments = serde_json::Map::new();
            arguments.insert(property.to_owned(), valid(shape, property)?);
            let reply = client::called(server, id, name, &Value::Object(arguments)).await?;
            id = id.saturating_add(1);
            probes.push(Probe {
                tool: name.into(),
                property: property.into(),
                reply,
            });
        }
    }
    Ok(probes.into_boxed_slice())
}

/// The name one listed tool states.
fn named(tool: &Value) -> Result<&str, Failure> {
    tool["name"]
        .as_str()
        .ok_or_else(|| Failure::Protocol(format!("a served tool names itself: {tool}").into()))
}

/// Every property one schema publishes, paired with the shape it publishes.
fn advertised<'listing>(
    schema: &'listing Value,
    tool: &str,
) -> Result<Vec<(&'listing str, &'listing Value)>, Failure> {
    let properties = schema["properties"].as_object().ok_or_else(|| {
        Failure::Protocol(format!("{tool}'s schema names its properties: {schema}").into())
    })?;
    client::claimed(!properties.is_empty(), || {
        format!("{tool}'s schema names at least one property: {schema}")
    })?;
    Ok(properties
        .iter()
        .map(|(name, shape)| (name.as_str(), shape))
        .collect())
}

/// One value of the type a property publishes.
///
/// A closed property takes its own first admitted token, so the value is one the
/// vocabulary states rather than one this test invented. Everything else takes a
/// value of the published JSON type; whether that value means anything to the
/// index is not what the probe asks.
fn valid(shape: &Value, property: &str) -> Result<Value, Failure> {
    match shape["type"].as_str() {
        Some("integer") => Ok(json!(1)),
        Some("array") => Ok(json!([first_token(&shape["items"], property)?])),
        Some("string") => first_token(shape, property),
        other => Err(Failure::Protocol(
            format!("{property} publishes a type this probe can fill: {other:?} in {shape}").into(),
        )),
    }
}

/// A closed property's first admitted token, or a plain string where it is open.
fn first_token(shape: &Value, property: &str) -> Result<Value, Failure> {
    match shape["enum"].as_array() {
        Some(vocabulary) => vocabulary.first().cloned().ok_or_else(|| {
            Failure::Protocol(format!("{property} admits at least one token: {shape}").into())
        }),
        None => Ok(json!("probe")),
    }
}

/// Every property a schema advertises is one its tool can name.
///
/// The gap this closes: a schema may publish an optional property no parameter
/// field names, and `deny_unknown_fields` then refuses every call that supplies
/// it. Nothing else is red — the listing is well formed, the required list is
/// exact, and no journey sends the argument — so the tool advertises an argument
/// it cannot be called with.
///
/// The reply is allowed to be anything except that refusal. A probe value is
/// meaningless to the index and most calls are missing a required argument, so
/// what is asserted is narrow and exact: the server never answers that it does
/// not know the key.
fn assert_every_advertised_property_is_accepted(journey: &Journey) {
    for probe in &journey.probes {
        let unknown = format!("unknown field `{}`", probe.property);
        let message = probe.reply["error"]["message"].as_str().unwrap_or_default();
        assert!(
            !message.contains(&unknown),
            "{} advertises {} and refuses it as an unknown argument: {}",
            probe.tool,
            probe.property,
            probe.reply
        );
    }
}

/// Every operation this server serves was probed with a property of its own.
///
/// The row that never ran is what this catches. A probe walk that stopped after
/// the first tool, or a schema whose properties were never reached, leaves the
/// claim above true of whatever it did probe and silent about the rest — and a
/// count comparison would pass on one tool advertising many properties while
/// another advertised none.
///
/// Held against [`TOOLS`] rather than against the listing the probes were read
/// from, because a walk that skipped a tool would skip it in both and the two
/// would agree. [`assert_exactly_the_public_operations`] has already pinned the
/// listing to this same inventory, so the pairing is exact.
fn assert_every_served_tool_was_probed(journey: &Journey) {
    let mut asked: Vec<&str> = journey.probes.iter().map(|probe| &*probe.tool).collect();
    asked.sort_unstable();
    asked.dedup();
    let mut served = TOOLS;
    served.sort_unstable();
    assert_eq!(
        asked, served,
        "every served operation is probed with a property it advertises: {}",
        journey.tools
    );
}

/// The handshake advertises tools, names the server, and pins the version.
fn assert_handshake(initialize: &Value) {
    assert!(
        initialize["result"]["capabilities"]["tools"].is_object(),
        "the server advertises tools: {initialize}"
    );
    // Equality, not merely an object. rmcp's default server info expands
    // `CARGO_CRATE_NAME` and `CARGO_PKG_VERSION` where rmcp itself is compiled,
    // so a server that never states its own reports the transport library and
    // its release to every client.
    assert_eq!(
        initialize["result"]["serverInfo"]["name"],
        json!("pedant-snippet"),
        "the server names itself, not its transport library: {initialize}"
    );
    assert_eq!(
        initialize["result"]["serverInfo"]["version"],
        json!(env!("CARGO_PKG_VERSION")),
        "the server reports its own release: {initialize}"
    );
    assert_eq!(
        initialize["result"]["protocolVersion"],
        json!(client::PROTOCOL),
        "the server negotiates the version the client requests: {initialize}"
    );
}

/// The listing is exactly the eight public operations, each annotated.
fn assert_exactly_the_public_operations(response: &Value) {
    let served = client::served(response, "the served listing");
    let names: Vec<&str> = served
        .iter()
        .map(|tool| named(tool).unwrap_or_else(|failure| panic!("{failure}")))
        .collect();
    assert_eq!(
        names, TOOLS,
        "the server serves exactly the public operations, in one order: {response}"
    );

    for tool in served {
        let annotations = &tool["annotations"];
        for (hint, published) in ANNOTATIONS {
            assert_eq!(
                annotations[hint],
                json!(published),
                "{} publishes {hint} as {published}: {annotations}",
                tool["name"]
            );
        }
        assert!(
            tool["description"]
                .as_str()
                .is_some_and(|stated| !stated.is_empty()),
            "{} describes itself: {tool}",
            tool["name"]
        );
    }
}

/// Every schema is a closed object stating exactly its required arguments.
///
/// The rows are passed in rather than reached for, so the listing under test and
/// the requirements it is held to arrive at this assertion the same way.
fn assert_every_schema_is_closed(journey: &Journey, required: &[Required]) {
    let response = &journey.tools;
    let served = client::served(response, "the served listing");
    assert_eq!(
        served.len(),
        required.len(),
        "every served tool has a written-down requirement row: {response}"
    );
    for (tool, row) in served.iter().zip(required) {
        assert_eq!(
            tool["name"],
            json!(row.tool),
            "the requirement rows are in listing order: {tool}"
        );
        let schema = &tool["inputSchema"];
        assert_eq!(
            schema["type"],
            json!("object"),
            "{}'s schema describes an object: {schema}",
            row.tool
        );
        assert_eq!(
            schema["required"],
            json!(row.arguments),
            "{}'s schema requires exactly its stated arguments: {schema}",
            row.tool
        );
        assert_eq!(
            schema["additionalProperties"],
            json!(false),
            "{}'s schema refuses an argument it does not name: {schema}",
            row.tool
        );
        for argument in row.arguments {
            assert!(
                schema["properties"][argument].is_object(),
                "{}'s schema describes its required {argument}: {schema}",
                row.tool
            );
        }
    }
}

/// Every malformed call is a protocol error, so no query ever ran.
fn assert_malformed_calls_stop_before_a_query(journey: &Journey) {
    client::assert_protocol_error(
        &journey.unknown_tool,
        INVALID_PARAMS,
        &["unknown tool: enclosing_unit"],
        "the tool this product replaced",
    );
    client::assert_protocol_error(
        &journey.misspelled_argument,
        INVALID_PARAMS,
        &["invalid parameters", "pth"],
        "a misspelled argument",
    );
    client::assert_protocol_error(
        &journey.missing_argument,
        INVALID_PARAMS,
        &["invalid parameters", "missing field `path`"],
        "arguments without the required path",
    );
    client::assert_protocol_error(
        &journey.wrong_type,
        INVALID_PARAMS,
        &["invalid parameters", "invalid type: string"],
        "a line that is not an integer",
    );
}
