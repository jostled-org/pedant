//! Non-allocating recognition of resolution-report wire field names.

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
pub(super) enum ReportField {
    Tier,
    Units,
    Definitions,
    References,
    Resolutions,
}
