use pedant_types::{Capability, Language};
use rmcp::model::CallToolResult;
use serde::Deserialize;

use super::super::{error_result, json_result};
use super::capabilities::parse_capability;
use super::outputs::{CapabilitySearchResult, finding_output};
use crate::index::WorkspaceIndex;

/// Deserialized arguments for `search_by_capability`.
#[derive(Deserialize)]
pub struct SearchByCapabilityParams {
    /// Single capability or intersection (e.g., `"network + crypto"`).
    pub pattern: Box<str>,
    /// Restrict results to findings from a specific language (e.g., `"python"`).
    #[serde(default)]
    pub language: Option<Box<str>>,
}

/// Handler: find crates whose profiles contain all requested capabilities.
pub fn search_by_capability(
    params: SearchByCapabilityParams,
    index: &WorkspaceIndex,
) -> CallToolResult {
    let required = match parse_capability_pattern(&params.pattern) {
        Ok(caps) => caps,
        Err(msg) => return error_result(msg),
    };
    let lang_filter = match params.language.as_deref().map(parse_language).transpose() {
        Ok(f) => f,
        Err(msg) => return error_result(msg),
    };

    let results: Box<[CapabilitySearchResult<'_>]> = index
        .all_profiles()
        .filter_map(|(name, profile)| {
            let matched: Box<[_]> = profile
                .findings
                .iter()
                .filter(|f| lang_filter.is_none_or(|l| f.language == Some(l)))
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let has_all = required
                .iter()
                .all(|r| matched.iter().any(|f| f.capability == *r));
            match has_all {
                true => Some(CapabilitySearchResult {
                    crate_name: name,
                    findings: matched
                        .iter()
                        .map(|f| finding_output(f))
                        .collect::<Vec<_>>()
                        .into_boxed_slice(),
                }),
                false => None,
            }
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    json_result(&results)
}

fn parse_language(name: &str) -> Result<Language, String> {
    match name {
        "python" => Ok(Language::Python),
        "javascript" => Ok(Language::JavaScript),
        "typescript" => Ok(Language::TypeScript),
        "go" => Ok(Language::Go),
        "bash" => Ok(Language::Bash),
        _ => Err(format!("unknown language: {name}")),
    }
}

fn parse_capability_pattern(pattern: &str) -> Result<Box<[Capability]>, String> {
    pattern
        .split('+')
        .map(|s| parse_capability(s.trim()))
        .collect::<Result<Vec<_>, _>>()
        .map(Vec::into_boxed_slice)
}
