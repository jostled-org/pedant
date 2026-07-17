//! Collection of qualified paths referenced by a file.
//!
//! Two sources feed the same list: `use` items (walked as trees, since one item
//! can declare many paths) and multi-segment paths appearing in expressions.
//! Expression paths repeat heavily, so they are deduplicated against a set;
//! `use` items are already distinct and are pushed straight through.

use std::collections::BTreeSet;
use std::fmt::Write;

use crate::ir::PATH_SEPARATOR;
use crate::ir::facts::{IrSpan, UsePathFact};

use super::syn_helpers::span_from;

/// Bound on `use` tree recursion, guarding against pathological nesting.
const MAX_USE_TREE_DEPTH: usize = 32;

/// Accumulates [`UsePathFact`]s, deduplicating expression paths.
pub(super) struct UsePathCollector {
    paths: Vec<UsePathFact>,
    /// Dedup set for expression paths (`O(log n)` instead of a linear scan).
    seen: BTreeSet<Box<str>>,
    /// Scratch buffer for path building, reused across items and expressions.
    buf: String,
}

impl UsePathCollector {
    pub(super) fn new() -> Self {
        Self {
            paths: Vec::new(),
            seen: BTreeSet::new(),
            buf: String::new(),
        }
    }

    /// Record every path declared by a `use` item's tree.
    pub(super) fn collect_use_tree(&mut self, tree: &syn::UseTree, span: IrSpan) {
        self.buf.clear();
        walk_use_tree(tree, &mut self.buf, 0, &mut self.paths, span);
    }

    /// Record a multi-segment path from an expression, if not already seen.
    /// Single-segment paths are bare identifiers and carry no path information.
    pub(super) fn emit_multi_segment_path(&mut self, path: &syn::Path) {
        if path.segments.len() <= 1 {
            return;
        }
        self.buf.clear();
        push_segment(&mut self.buf, &path.segments[0].ident);
        for seg in path.segments.iter().skip(1) {
            write!(self.buf, "{PATH_SEPARATOR}{}", seg.ident).ok();
        }

        let span = path.segments.first().map_or_else(
            || {
                path.leading_colon
                    .map_or(proc_macro2::Span::call_site(), |c| c.spans[0])
            },
            |s| s.ident.span(),
        );

        let path_str = self.buf.as_str();
        if self.seen.contains(path_str) {
            return;
        }
        self.seen.insert(Box::from(path_str));
        self.paths.push(UsePathFact {
            path: Box::from(path_str),
            span: span_from(span.start()),
        });
    }

    pub(super) fn finish(self) -> Box<[UsePathFact]> {
        self.paths.into_boxed_slice()
    }
}

/// Append `ident` to `buf`, inserting a separator unless `buf` is empty.
fn push_segment(buf: &mut String, ident: &impl std::fmt::Display) {
    match buf.is_empty() {
        true => {
            write!(buf, "{ident}").ok();
        }
        false => {
            write!(buf, "{PATH_SEPARATOR}{ident}").ok();
        }
    }
}

/// Walk a `use` tree depth-first, emitting one fact per leaf. `buf` holds the
/// prefix accumulated so far and is truncated back on the way out.
fn walk_use_tree(
    tree: &syn::UseTree,
    buf: &mut String,
    depth: usize,
    paths: &mut Vec<UsePathFact>,
    span: IrSpan,
) {
    if depth > MAX_USE_TREE_DEPTH {
        return;
    }
    let restore_len = buf.len();
    match tree {
        syn::UseTree::Path(syn::UsePath { ident, tree, .. }) => {
            push_segment(buf, ident);
            walk_use_tree(tree, buf, depth + 1, paths, span);
        }
        syn::UseTree::Name(syn::UseName { ident, .. }) => {
            push_segment(buf, ident);
            paths.push(UsePathFact {
                path: Box::from(buf.as_str()),
                span,
            });
        }
        syn::UseTree::Rename(syn::UseRename { ident, .. }) => {
            push_segment(buf, ident);
            paths.push(UsePathFact {
                path: Box::from(buf.as_str()),
                span,
            });
        }
        syn::UseTree::Glob(_) => {
            paths.push(UsePathFact {
                path: Box::from(&buf[..restore_len]),
                span,
            });
        }
        syn::UseTree::Group(syn::UseGroup { items, .. }) => {
            for item in items {
                walk_use_tree(item, buf, depth + 1, paths, span);
            }
        }
    }
    buf.truncate(restore_len);
}
