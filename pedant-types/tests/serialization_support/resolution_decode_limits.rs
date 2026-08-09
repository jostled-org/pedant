//! External proofs for caller-bounded resolution-report decoding.

use pedant_types::resolution::{ResolutionReport, ResolutionReportError, ResolutionReportLimits};
use serde_json::Value;
use std::ptr;

use crate::resolution_fixture::{valid_report, valid_report_json};

/// Prove all four top-level sequences refuse their established capacity error.
pub fn assert_each_collection_is_bounded() {
    let encoded = serde_json::to_string(&valid_report()).expect("the valid report serializes");
    assert_limit_refusal(
        &encoded,
        ResolutionReportLimits {
            max_units: 1,
            ..ResolutionReportLimits::default()
        },
        ResolutionReportError::UnitCapacityExceeded { limit: 1 },
    );
    assert_limit_refusal(
        &encoded,
        ResolutionReportLimits {
            max_definitions: 2,
            ..ResolutionReportLimits::default()
        },
        ResolutionReportError::DefinitionCapacityExceeded { limit: 2 },
    );
    assert_limit_refusal(
        &encoded,
        ResolutionReportLimits {
            max_references: 1,
            ..ResolutionReportLimits::default()
        },
        ResolutionReportError::ReferenceCapacityExceeded { limit: 1 },
    );
    assert_limit_refusal(
        &resolution_first_json(),
        ResolutionReportLimits {
            max_references: 1,
            ..ResolutionReportLimits::default()
        },
        ResolutionReportError::ResolutionCapacityExceeded { limit: 1 },
    );
}

/// Prove exact configured limits and the default boundary accept valid input.
pub fn assert_default_and_configured_valid_decoding() {
    let report = valid_report();
    let encoded = serde_json::to_string(&report).expect("the valid report serializes");
    let configured = decode(
        &encoded,
        ResolutionReportLimits {
            max_units: 2,
            max_definitions: 3,
            max_references: 2,
        },
    )
    .expect("exact collection limits admit a valid report");
    let default = decode(&encoded, ResolutionReportLimits::default())
        .expect("the explicit default limits admit a valid report");
    let ordinary: ResolutionReport =
        serde_json::from_str(&encoded).expect("ordinary Deserialize retains default behavior");
    let sequence = report_sequence();
    let positional = ResolutionReport::deserialize_with_limits(
        sequence,
        ResolutionReportLimits {
            max_units: 2,
            max_definitions: 3,
            max_references: 2,
        },
    )
    .expect("serde's positional struct representation remains supported");

    assert_eq!(configured, report);
    assert_eq!(default, report);
    assert_eq!(ordinary, report);
    assert_eq!(positional, report);
    assert!(
        ptr::eq(
            configured.definitions()[0].span().file(),
            configured.references()[0].span().file(),
        ),
        "bounded decoding retains path interning",
    );
    assert_eq!(
        serde_json::to_string(&configured).expect("the bounded report serializes"),
        encoded,
        "bounded decoding preserves the stable wire shape",
    );
}

/// Prove custom map decoding retains derive-equivalent field errors.
pub fn assert_map_field_errors() {
    let fields = report_fields();
    let duplicate = format!(
        "{{\"tier\":{},\"tier\":{},\"units\":{},\"definitions\":{},\"references\":{},\"resolutions\":{}}}",
        fields.tier,
        fields.tier,
        fields.units,
        fields.definitions,
        fields.references,
        fields.resolutions,
    );
    assert_decode_message(&duplicate, "duplicate field `tier`");

    let missing = format!(
        "{{\"tier\":{},\"units\":{},\"definitions\":{},\"resolutions\":{}}}",
        fields.tier, fields.units, fields.definitions, fields.resolutions,
    );
    assert_decode_message(&missing, "missing field `references`");

    let unknown = format!(
        "{{\"tier\":{},\"units\":{},\"definitions\":{},\"references\":{},\"resolutions\":{},\"intruder\":null}}",
        fields.tier, fields.units, fields.definitions, fields.references, fields.resolutions,
    );
    assert_decode_message(&unknown, "unknown field `intruder`");
}

struct ReportFields {
    tier: Value,
    units: Value,
    definitions: Value,
    references: Value,
    resolutions: Value,
}

fn report_fields() -> ReportFields {
    let mut report = valid_report_json();
    ReportFields {
        tier: report["tier"].take(),
        units: report["units"].take(),
        definitions: report["definitions"].take(),
        references: report["references"].take(),
        resolutions: report["resolutions"].take(),
    }
}

fn report_sequence() -> Value {
    let fields = report_fields();
    Value::Array(vec![
        fields.tier,
        fields.units,
        fields.definitions,
        fields.references,
        fields.resolutions,
    ])
}

fn resolution_first_json() -> String {
    let fields = report_fields();
    format!(
        "{{\"tier\":{},\"units\":{},\"definitions\":{},\"resolutions\":{},\"references\":{}}}",
        fields.tier, fields.units, fields.definitions, fields.resolutions, fields.references,
    )
}

fn decode(
    encoded: &str,
    limits: ResolutionReportLimits,
) -> Result<ResolutionReport, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_str(encoded);
    ResolutionReport::deserialize_with_limits(&mut deserializer, limits)
}

fn assert_limit_refusal(
    encoded: &str,
    limits: ResolutionReportLimits,
    expected: ResolutionReportError,
) {
    let reported = decode(encoded, limits)
        .expect_err("the configured capacity must refuse the report")
        .to_string();
    assert!(
        reported.starts_with(&expected.to_string()),
        "expected {expected:?}, got {reported}",
    );
}

fn assert_decode_message(encoded: &str, expected: &str) {
    let reported = decode(encoded, ResolutionReportLimits::default())
        .expect_err("the malformed map must be refused")
        .to_string();
    assert!(
        reported.starts_with(expected),
        "expected `{expected}`, got `{reported}`",
    );
}
