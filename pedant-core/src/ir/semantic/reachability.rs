//! Call graph reachability analysis.
//!
//! Computes which functions are transitively reachable from public entry
//! points. Call graph edges and function entries are precomputed by
//! `FnContext` and assembled in `SemanticFileAnalysis::build`; this module
//! provides the reachability computation and line-level lookup.

use super::FnEntry;

/// Compute the set of function names reachable from public entry points.
///
/// Returns an owned `BTreeSet<Box<str>>` suitable for caching.
pub(super) fn compute_reachable_names(
    fns: &[FnEntry],
    edges: &[(Box<str>, Box<str>)],
) -> std::collections::BTreeSet<Box<str>> {
    reachable_set(fns, edges)
        .into_iter()
        .map(Box::from)
        .collect()
}

/// Check whether a single line falls within a reachable function,
/// using a cached set of reachable names.
///
/// Uses binary search on start lines (fn_entries are sorted by source
/// position) to find a candidate, then verifies the line falls within
/// the function's span.
pub(super) fn is_line_in_reachable_fn(
    fns: &[FnEntry],
    reachable_names: &std::collections::BTreeSet<Box<str>>,
    line: usize,
) -> bool {
    let idx = fns.partition_point(|(_, start, _, _)| *start <= line);
    match idx.checked_sub(1) {
        Some(i) => {
            let (name, _, end, _) = &fns[i];
            line <= *end && reachable_names.contains(name)
        }
        None => false,
    }
}

/// Precompute the set of all function names reachable from entry points via BFS.
fn reachable_set<'a>(
    fns: &'a [FnEntry],
    edges: &'a [(Box<str>, Box<str>)],
) -> std::collections::BTreeSet<&'a str> {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (caller, callee) in edges {
        adj.entry(caller).or_default().push(callee);
    }

    let mut visited: BTreeSet<&str> = BTreeSet::new();
    let mut queue = VecDeque::new();

    for (name, _, _, is_entry) in fns {
        if *is_entry {
            visited.insert(name);
            queue.push_back(&**name);
        }
    }

    while let Some(current) = queue.pop_front() {
        let callees = match adj.get(current) {
            Some(c) => c,
            None => continue,
        };
        for callee in callees {
            if visited.insert(callee) {
                queue.push_back(callee);
            }
        }
    }

    visited
}
