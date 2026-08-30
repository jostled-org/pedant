//! Reading one call's arguments.
//!
//! Every parameter set this registry serves is flat and closed. Flat, because a
//! tool argument list is what a client fills in and a nested request object
//! would make the schema describe this crate's internal shapes rather than the
//! question. Closed, because a misspelled argument that was ignored would answer
//! a different question than the one asked — the same mistake clap reports for a
//! misspelled flag, reported the same way.
//!
//! The page a request asks for is not built here. It is one of the rules both
//! transports answer to, so it is stated beside every other one in
//! [`crate::operation`].

use rmcp::ErrorData;
use rmcp::model::JsonObject;
use serde::Deserialize;
use serde_json::Value;

/// Read one call's arguments.
///
/// A misspelled or missing argument means the tool never ran, so the refusal is
/// the same `-32602` a name this server does not serve gets.
pub(super) fn parameters<T: for<'any> Deserialize<'any>>(
    arguments: JsonObject,
) -> Result<T, ErrorData> {
    serde_json::from_value(Value::Object(arguments)).map_err(|failure| {
        ErrorData::invalid_params(format!("invalid parameters: {failure}"), None)
    })
}
