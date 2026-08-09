//! The one `use`-tree walk.
//!
//! Both the authoritative import sites and the capability-oriented flat path
//! list come from the leaves this walk produces, so an import tree is parsed
//! exactly once per source.

/// One leaf of a `use` tree: the path it names and how it binds.
pub(super) struct ImportLeaf {
    pub(super) segments: Box<[Box<str>]>,
    pub(super) alias: Option<Box<str>>,
    pub(super) glob: bool,
}

/// Every path one `use` item declares, in declaration order.
///
/// The walk carries its own stack rather than the call stack, so nesting costs
/// heap and not frames and no depth bound has to drop leaves. Every leaf the
/// tree names is therefore stated, and an absent import site means the source
/// declared none.
pub(super) fn use_tree_leaves(tree: &syn::UseTree) -> Box<[ImportLeaf]> {
    let mut leaves = Vec::new();
    let mut prefix: Vec<Box<str>> = Vec::new();
    let mut pending = vec![Step::Enter(tree)];
    while let Some(step) = pending.pop() {
        match step {
            Step::Enter(node) => enter(node, &mut prefix, &mut pending, &mut leaves),
            Step::Restore(depth) => prefix.truncate(depth),
        }
    }
    leaves.into_boxed_slice()
}

/// One unit of pending work: a subtree still to walk, or the prefix length to
/// return to once the subtree above it is done.
enum Step<'a> {
    Enter(&'a syn::UseTree),
    Restore(usize),
}

/// Walk one node, pushing whatever it leaves to do.
///
/// Group items are pushed in reverse so the stack pops them in declaration
/// order, and a `Restore` sits under every prefix a `use a::…` segment pushed.
fn enter<'a>(
    tree: &'a syn::UseTree,
    prefix: &mut Vec<Box<str>>,
    pending: &mut Vec<Step<'a>>,
    leaves: &mut Vec<ImportLeaf>,
) {
    match tree {
        syn::UseTree::Path(syn::UsePath { ident, tree, .. }) => {
            pending.push(Step::Restore(prefix.len()));
            prefix.push(ident.to_string().into_boxed_str());
            pending.push(Step::Enter(tree));
        }
        syn::UseTree::Name(syn::UseName { ident }) => leaves.push(leaf(prefix, ident, None)),
        syn::UseTree::Rename(syn::UseRename { ident, rename, .. }) => {
            let alias = rename.to_string().into_boxed_str();
            leaves.push(leaf(prefix, ident, Some(alias)));
        }
        syn::UseTree::Glob(_) => leaves.push(ImportLeaf {
            segments: prefix.to_vec().into_boxed_slice(),
            alias: None,
            glob: true,
        }),
        syn::UseTree::Group(syn::UseGroup { items, .. }) => {
            pending.extend(items.iter().rev().map(Step::Enter));
        }
    }
}

fn leaf(prefix: &[Box<str>], ident: &syn::Ident, alias: Option<Box<str>>) -> ImportLeaf {
    let segments: Box<[Box<str>]> = prefix
        .iter()
        .cloned()
        .chain(std::iter::once(ident.to_string().into_boxed_str()))
        .collect();
    ImportLeaf {
        segments,
        alias,
        glob: false,
    }
}
