#[cfg(feature = "checks")]
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

/// Judgment-only: `style/mixed_concerns.rs` is the sole consumer. Its siblings
/// below are substrate, consumed by `ir/extract`, so the gate is per item.
#[cfg(feature = "checks")]
pub(crate) fn bfs_component<'a>(
    start: &'a str,
    adj: &BTreeMap<&'a str, Vec<&'a str>>,
    visited: &mut BTreeSet<&'a str>,
) -> Vec<&'a str> {
    let mut component = Vec::new();
    let mut queue = VecDeque::new();
    queue.push_back(start);
    visited.insert(start);
    while let Some(current) = queue.pop_front() {
        component.push(current);
        for neighbor in adj[current].iter().copied().filter(|n| visited.insert(n)) {
            queue.push_back(neighbor);
        }
    }
    component.sort_unstable();
    component
}

/// Iterate every unique pair `(i, j)` where `i < j < len`.
pub(crate) fn for_each_pair(len: usize, mut emit: impl FnMut(usize, usize)) {
    (0..len).for_each(|i| {
        ((i + 1)..len).for_each(|j| {
            emit(i, j);
        });
    });
}

pub(crate) fn extend_pairwise_edges(names: &[Arc<str>], edges: &mut Vec<(Arc<str>, Arc<str>)>) {
    let len = names.len();
    edges.reserve(len * len.saturating_sub(1) / 2);
    for_each_pair(len, |i, j| {
        edges.push((Arc::clone(&names[i]), Arc::clone(&names[j])));
    });
}

pub(crate) fn extend_edges_from_names(
    owner: &Arc<str>,
    type_names: &[Arc<str>],
    edges: &mut Vec<(Arc<str>, Arc<str>)>,
) {
    edges.extend(
        type_names
            .iter()
            .map(|tn| (Arc::clone(owner), Arc::clone(tn))),
    );
}
