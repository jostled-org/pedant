//! What a malformed wire case is, and how one is run against the validator.
//!
//! The case tables state which reports are malformed; this module states what a
//! case *is*. Keeping the two apart lets the assertions depend on the vocabulary
//! without reaching into a table for it.
//!
//! The two construction boundaries are not symmetric, and `BuilderReach` is
//! where that asymmetry is written down rather than inferred from the size of
//! the two tables.

use pedant_types::resolution::{ResolutionReport, ResolutionReportError};
use serde_json::Value;

use crate::resolution_fixture::valid_report_json;

/// One malformed wire report and the exact validator refusal it must produce.
pub struct MalformedCase {
    /// Human-readable name of the invariant family under test.
    pub label: &'static str,
    /// Mutation applied to the fixture report's wire form.
    pub mutate: fn(&mut Value),
    /// The error the shared validator must return.
    pub expected: ResolutionReportError,
    /// Whether a writer can state this shape through the builder.
    pub reach: BuilderReach,
}

/// Whether the other construction boundary can produce a malformed family.
///
/// `finish` sorts, assigns dense identifiers, and takes branded handles, so
/// several wire families cannot exist on that side. Every family a writer *can*
/// state carries a `finish` case of the same label, and this field says which is
/// which.
#[derive(PartialEq, Eq)]
pub enum BuilderReach {
    /// A writer can state this shape, so a `finish` case must mirror it.
    Statable,
    /// `finish` cannot produce this shape, for the stated reason.
    WireOnly(&'static str),
}

/// Why `finish` cannot name a record the report does not hold.
pub const BRANDED: &str = "a writer names records through branded handles, \
    so it cannot name one the report does not hold";

/// Why `finish` cannot emit an identifier that is not its own sorted position.
pub const DENSE: &str = "`finish` assigns each identifier from the position its own sort produced";

/// Why `finish` cannot emit an unsorted collection.
pub const SORTED: &str = "`finish` sorts every collection before it validates";

/// Why `finish` cannot emit a record whose language contradicts its unit.
pub const COPIED_LANGUAGE: &str =
    "a writer states no record language; `finish` copies each record's unit";

/// Deserialize a mutated wire report and return the refusal it produced.
pub fn refusal(case: &MalformedCase) -> String {
    let mut wire = valid_report_json();
    (case.mutate)(&mut wire);
    match serde_json::from_value::<ResolutionReport>(wire) {
        Ok(_) => panic!("{}: the validator accepted a malformed report", case.label),
        Err(error) => error.to_string(),
    }
}
