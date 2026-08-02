//! The success shape both transports serialize.

use serde::{Deserialize, Serialize};

use pedant_syntax::SourceUnit;

/// One extraction result, present or absent.
///
/// The CLI's JSON output and the MCP tool's success content are this one shape,
/// so a consumer reads `unit` the same way on either transport. Absence is an
/// explicit `null`, never a missing field.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Extraction {
    /// The declaration containing the requested location, when one exists.
    pub unit: Option<SourceUnit>,
}

impl Extraction {
    /// Render the canonical JSON both transports emit.
    ///
    /// The rendering is a `String` rather than the `Box<str>` this codebase
    /// holds immutable data in, because no caller holds it: the CLI writes the
    /// bytes and drops them, and the MCP transport moves them into one content
    /// block. Boxing would reallocate and copy the whole declaration to shed a
    /// capacity nothing outlives.
    ///
    /// # Errors
    ///
    /// Returns the serializer's error when the unit cannot be encoded.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}
