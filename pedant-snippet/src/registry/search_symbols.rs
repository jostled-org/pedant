//! `search_symbols`: every named structure one query selects.

use pedant_snippet::{MatchMode, PageCursor, SymbolQuery};
use pedant_types::{Language, StructureKind};
use rmcp::ErrorData;
use rmcp::model::JsonObject;
use serde::Deserialize;

use crate::operation::{Operation, page};

use super::params::parameters;
use super::schema::{
    KIND_FILTER, LANGUAGE_FILTER, MATCH_MODE, OWNER_NAME_FILTER, PATH_PREFIX_FILTER, SEARCH_TEXT,
    choice, page_properties, property, schema,
};

/// What `search_symbols` accepts.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Params {
    text: Box<str>,
    mode: MatchMode,
    #[serde(default)]
    language: Option<Language>,
    #[serde(default)]
    kind: Option<StructureKind>,
    #[serde(default)]
    owner_name: Option<Box<str>>,
    #[serde(default)]
    path_prefix: Option<Box<str>>,
    #[serde(default)]
    page_size: Option<u32>,
    #[serde(default)]
    cursor: Option<PageCursor>,
}

/// The schema a client validates its arguments against.
pub(super) fn definition(max_page_items: u32) -> JsonObject {
    let mut properties = vec![
        ("text", property("string", SEARCH_TEXT)),
        (
            "mode",
            choice(MATCH_MODE, &MatchMode::ALL.map(MatchMode::token)),
        ),
        (
            "language",
            choice(LANGUAGE_FILTER, &Language::ALL.map(Language::token)),
        ),
        (
            "kind",
            choice(KIND_FILTER, &StructureKind::ALL.map(StructureKind::token)),
        ),
        ("owner_name", property("string", OWNER_NAME_FILTER)),
        ("path_prefix", property("string", PATH_PREFIX_FILTER)),
    ];
    properties.extend(page_properties(max_page_items));
    schema(properties, &["text", "mode"])
}

/// The question one call states.
pub(super) fn requested(arguments: JsonObject) -> Result<Operation, ErrorData> {
    let stated: Params = parameters(arguments)?;
    let query = SymbolQuery {
        text: stated.text,
        mode: stated.mode,
        language: stated.language,
        kind: stated.kind,
        owner_name: stated.owner_name,
        path_prefix: stated.path_prefix,
    };
    Ok(Operation::SearchSymbols(
        query,
        page(stated.page_size, stated.cursor),
    ))
}
