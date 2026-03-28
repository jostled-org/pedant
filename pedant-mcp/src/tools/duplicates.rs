use std::collections::BTreeMap;

use pedant_core::ir::FnFingerprint;
use rmcp::model::CallToolResult;
use serde::{Deserialize, Serialize};

use super::{error_result, json_result};
use crate::index::WorkspaceIndex;

// ---------------------------------------------------------------------------
// Parameter struct
// ---------------------------------------------------------------------------

/// Deserialized arguments for `find_structural_duplicates`.
#[derive(Deserialize)]
pub struct FindStructuralDuplicatesParams {
    /// Crate name or `"workspace"`.
    pub scope: Box<str>,
    /// Minimum fact count to include a function (default 3).
    #[serde(default)]
    pub min_fact_count: Option<usize>,
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct DuplicateGroup<'a> {
    skeleton_hash: u64,
    functions: Vec<DuplicateFnEntry<'a>>,
    exact_subgroups: Vec<ExactSubgroup<'a>>,
}

#[derive(Serialize)]
struct DuplicateFnEntry<'a> {
    name: &'a str,
    file: &'a str,
    line: usize,
    exact_hash: u64,
    fact_count: usize,
}

#[derive(Serialize)]
struct ExactSubgroup<'a> {
    exact_hash: u64,
    functions: Vec<&'a str>,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handler: find structurally duplicated functions across files in a crate or workspace.
pub fn find_structural_duplicates(
    params: FindStructuralDuplicatesParams,
    index: &WorkspaceIndex,
) -> CallToolResult {
    let min_facts = params.min_fact_count.unwrap_or(3);

    let fingerprints: Vec<(&str, &FnFingerprint)> = match resolve_fingerprints(&params.scope, index)
    {
        Ok(fps) => fps,
        Err(r) => return r,
    };

    // Filter trivial functions and group by skeleton_hash
    let mut skeleton_groups: BTreeMap<u64, Vec<(&str, &FnFingerprint)>> = BTreeMap::new();
    for (file, fp) in fingerprints {
        if fp.fact_count >= min_facts {
            skeleton_groups
                .entry(fp.skeleton_hash)
                .or_default()
                .push((file, fp));
        }
    }

    // Keep only groups with 2+ members (actual duplicates)
    let groups: Vec<DuplicateGroup<'_>> = skeleton_groups
        .into_iter()
        .filter(|(_, members)| members.len() >= 2)
        .map(|(skeleton_hash, members)| build_group(skeleton_hash, &members))
        .collect();

    json_result(&groups)
}

fn build_group<'a>(
    skeleton_hash: u64,
    members: &[(&'a str, &'a FnFingerprint)],
) -> DuplicateGroup<'a> {
    let functions: Vec<DuplicateFnEntry<'_>> = members
        .iter()
        .map(|(file, fp)| DuplicateFnEntry {
            name: &fp.name,
            file,
            line: fp.span.line,
            exact_hash: fp.exact_hash,
            fact_count: fp.fact_count,
        })
        .collect();

    // Partition by exact_hash
    let mut exact_map: BTreeMap<u64, Vec<&'a str>> = BTreeMap::new();
    for (_, fp) in members {
        exact_map.entry(fp.exact_hash).or_default().push(&fp.name);
    }
    let exact_subgroups: Vec<ExactSubgroup<'_>> = exact_map
        .into_iter()
        .map(|(exact_hash, names)| ExactSubgroup {
            exact_hash,
            functions: names,
        })
        .collect();

    DuplicateGroup {
        skeleton_hash,
        functions,
        exact_subgroups,
    }
}

// ---------------------------------------------------------------------------
// Scope resolution
// ---------------------------------------------------------------------------

fn resolve_fingerprints<'a>(
    scope: &str,
    index: &'a WorkspaceIndex,
) -> Result<Vec<(&'a str, &'a FnFingerprint)>, CallToolResult> {
    match scope {
        "workspace" => Ok(collect_all_fingerprints(index)),
        _ => index
            .crate_files(scope)
            .map(collect_file_fingerprints)
            .ok_or_else(|| error_result(format!("unknown scope: {scope}"))),
    }
}

fn collect_file_fingerprints<'a>(
    files: impl Iterator<Item = (&'a str, &'a pedant_core::AnalysisResult)>,
) -> Vec<(&'a str, &'a FnFingerprint)> {
    files
        .flat_map(|(path, r)| r.fn_fingerprints.iter().map(move |fp| (path, fp)))
        .collect()
}

fn collect_all_fingerprints(index: &WorkspaceIndex) -> Vec<(&str, &FnFingerprint)> {
    let files = index
        .crate_names()
        .flat_map(|name| index.crate_files(name).into_iter().flatten());
    collect_file_fingerprints(files)
}
