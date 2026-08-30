//! 9.T7: the extraction product routes are gone, and the syntax primitive is
//! not.
//!
//! The retained primitive is called directly. Both withdrawn transport routes
//! are tested through the spawned CLI and real MCP registry.

use pedant_snippet::{Location, SourceUnitKind, enclosing_unit};
use pedant_syntax::SyntaxLanguage;
use serde_json::json;

use crate::child::Server;
use crate::failure::Failure;
use crate::journeys::client;
use crate::journeys::fixture::{Fixture, root_arguments};
use crate::journeys::outcome::{assert_clean, assert_usage_error, run};

/// The tool name the cutover withdrew from the registry.
const WITHDRAWN_TOOL: &str = "enclosing_unit";

/// The source this journey reads its retained-primitive answer out of.
const PRIMITIVE_SOURCE: &str = "fn make() -> u32 {\n    0\n}\n";

/// The declaration that source states, which is the file without its last
/// newline: a unit's text is its own bytes, and the terminator belongs to the
/// file.
const PRIMITIVE_DECLARATION: &str = "fn make() -> u32 {\n    0\n}";

#[tokio::test]
async fn legacy_extraction_product_routes_are_absent_and_syntax_primitive_remains() {
    assert_the_retained_syntax_primitive_answers();
    assert_neither_transport_serves_the_old_routes().await;
}

/// The retained syntax primitive still answers one point lookup.
///
/// Called through this crate's own re-export, which is the claim: a consumer
/// that held one dependency for the point lookup keeps holding one.
fn assert_the_retained_syntax_primitive_answers() {
    let found = enclosing_unit(
        PRIMITIVE_SOURCE,
        SyntaxLanguage::Rust,
        Location {
            line: 2,
            column: None,
        },
    )
    .expect("the retained primitive finds the declaration containing the point");
    assert_eq!(
        found.kind,
        SourceUnitKind::Function,
        "and states what it is: {found:?}"
    );
    assert_eq!(
        &*found.text, PRIMITIVE_DECLARATION,
        "and returns its exact bytes"
    );
}

/// Neither transport serves the old routes.
///
/// The CLI is asked for the withdrawn command. The server is checked through
/// both its published listing and direct dispatch.
async fn assert_neither_transport_serves_the_old_routes() {
    let fixture = Fixture::new();
    let refused = run(
        fixture.root(),
        &["extract", "--file", "crate-a/src/lib.rs", "--line", "1"],
        "the withdrawn extract command",
    )
    .await
    .unwrap_or_else(|failure| panic!("the refused run completes: {failure}"));
    assert_usage_error(&refused, "the withdrawn extract command", "extract");

    let ((), termination) = client::session(
        &root_arguments(&fixture),
        "the withdrawn-tool journey",
        async |server| the_server_serves_no_such_tool(server).await,
    )
    .await;
    assert_clean(&termination, "the withdrawn-tool session");
}

/// The registry neither lists the withdrawn tool nor dispatches it.
async fn the_server_serves_no_such_tool(server: &mut Server) -> Result<(), Failure> {
    client::initialized(server).await?;
    let id = server.next_id();
    let listed = client::listed(server, id).await?;
    let tools = client::tools(&listed, "the withdrawn-tool listing")?;
    client::claimed(
        !tools
            .iter()
            .any(|tool| tool["name"] == json!(WITHDRAWN_TOOL)),
        || format!("the registry no longer publishes {WITHDRAWN_TOOL}: {listed}"),
    )?;

    let response = client::asked(server, WITHDRAWN_TOOL, &json!({})).await?;
    client::claimed_protocol_error(
        &response,
        client::INVALID_PARAMS,
        &[&format!("unknown tool: {WITHDRAWN_TOOL}")],
        "the withdrawn enclosing-unit tool",
    )
}
