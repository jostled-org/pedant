use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;

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
        for &neighbor in &adj[current] {
            if visited.insert(neighbor) {
                queue.push_back(neighbor);
            }
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

pub(crate) fn extend_pairwise_edges(names: &[Rc<str>], edges: &mut Vec<(Rc<str>, Rc<str>)>) {
    let len = names.len();
    edges.reserve(len * len.saturating_sub(1) / 2);
    for_each_pair(len, |i, j| {
        edges.push((Rc::clone(&names[i]), Rc::clone(&names[j])));
    });
}

pub(crate) fn extend_edges_from_names(
    owner: &Rc<str>,
    type_names: &[Rc<str>],
    edges: &mut Vec<(Rc<str>, Rc<str>)>,
) {
    edges.extend(
        type_names
            .iter()
            .map(|tn| (Rc::clone(owner), Rc::clone(tn))),
    );
}
