use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::check_config::CheckConfig;
use crate::graph::bfs_component;
use crate::ir::{FileIr, IrSpan};
use crate::violation::{Violation, ViolationType};

use super::common::emit_violation;

pub(super) fn check_mixed_concerns(
    ir: &FileIr,
    config: &CheckConfig,
    fp: &Arc<str>,
    violations: &mut Vec<Violation>,
) {
    if !config.check_mixed_concerns || ir.type_defs.len() < 2 {
        return;
    }

    let defined_types: BTreeSet<&str> = ir.type_defs.iter().map(|td| td.name.as_ref()).collect();

    let type_def_iter = ir
        .type_defs
        .iter()
        .flat_map(|td| td.edges.iter().map(|(a, b)| (a.as_ref(), b.as_ref())));

    let impl_iter = ir
        .impl_blocks
        .iter()
        .flat_map(|ib| ib.edges.iter().map(|(a, b)| (a.as_ref(), b.as_ref())));

    let mut fn_edges: Vec<(&str, &str)> = Vec::new();
    for func in &ir.functions {
        if func.item_depth == 0 {
            let names = &func.signature_type_names;
            crate::graph::for_each_pair(names.len(), |i, j| {
                fn_edges.push((names[i].as_ref(), names[j].as_ref()));
            });
        }
        fn_edges.extend(
            func.body_type_edges
                .iter()
                .map(|(a, b)| (a.as_ref(), b.as_ref())),
        );
    }

    let all_edges = type_def_iter.chain(impl_iter).chain(fn_edges);

    let Some(message) = find_disconnected_groups(&defined_types, all_edges) else {
        return;
    };
    emit_violation(
        violations,
        fp,
        IrSpan { line: 1, column: 0 },
        ViolationType::MixedConcerns,
        message,
    );
}

fn find_disconnected_groups<'a>(
    defined_types: &BTreeSet<&'a str>,
    all_edges: impl Iterator<Item = (&'a str, &'a str)>,
) -> Option<Box<str>> {
    let mut adj: BTreeMap<&str, Vec<&str>> = defined_types
        .iter()
        .map(|&name| (name, Vec::new()))
        .collect();
    for (src, dst) in all_edges {
        if src == dst || !defined_types.contains(src) || !defined_types.contains(dst) {
            continue;
        }
        adj.entry(src).or_default().push(dst);
        adj.entry(dst).or_default().push(src);
    }

    let mut visited: BTreeSet<&str> = BTreeSet::new();
    let mut components: Vec<Vec<&str>> = Vec::new();

    for name in defined_types {
        if visited.contains(name) {
            continue;
        }
        components.push(bfs_component(name, &adj, &mut visited));
    }

    if components.len() < 2 {
        return None;
    }

    components.sort_by(|a, b| a.first().cmp(&b.first()));
    let mut result = String::from("disconnected type groups: ");
    for (i, c) in components.iter().enumerate() {
        if i > 0 {
            result.push_str(", ");
        }
        result.push('{');
        result.push_str(&c.join(", "));
        result.push('}');
    }
    Some(result.into_boxed_str())
}
