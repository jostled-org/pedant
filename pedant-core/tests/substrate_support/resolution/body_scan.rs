//! Which function bodies one production source declares, and how each is
//! shaped.
//!
//! One walk, three measures: how many statements a body states, how deeply it
//! nests, and what its tokens are. The third is what makes a duplicate visible
//! across two modules, which no single-file reading can be.
//!
//! The fold from a set of parsed owners to their bodies, and the fold from those
//! bodies to the shapes written more than once, live here too. Two surfaces ask
//! the duplicate question — the Go plan surface and the completed
//! code-intelligence product — and the two copies of the fold were themselves
//! the duplicate each of them exists to report.

use std::collections::BTreeMap;

use quote::ToTokens;
use syn::visit::Visit;

use crate::resolution::body_nesting::nesting_depth;

/// The smallest body a duplicate claim ranges over, in statements.
///
/// One-statement bodies are accessors and forwarders. Two structs that each
/// return `&self.root` state the same statement about different types, and
/// calling that a duplicate would force a rename rather than a fix. From two
/// statements up, an identical body is copied code.
pub(crate) const MIN_DUPLICATE_STATEMENTS: usize = 2;

/// One function body a production source declares.
pub(crate) struct Body {
    /// The function's name, as a failure would report it.
    pub(crate) name: Box<str>,
    /// How many statements the body states at its own level.
    pub(crate) statements: usize,
    /// The deepest control-flow nesting the body reaches.
    pub(crate) nesting: usize,
    /// The body's tokens, whitespace-normalized, so two copies compare equal.
    pub(crate) shape: Box<str>,
}

/// Every function body one source declares, free, inherent, or defaulted.
pub(crate) fn bodies(file: &syn::File) -> Box<[Body]> {
    let mut collector = BodyCollector::default();
    collector.visit_file(file);
    collector.found.into_boxed_slice()
}

/// Every body of a set of parsed owners, paired with the owner that declares it.
///
/// Read once for a whole case. Rendering every block of a hundred-odd files is
/// the dominant cost in each of its callers, and the duplicate claim, the
/// nesting claim, and the ordering claim ask it of the same set.
pub(crate) fn bodies_by_owner<'read>(
    owners: impl Iterator<Item = (&'read str, &'read syn::File)>,
) -> Box<[(Box<str>, Body)]> {
    owners
        .flat_map(|(path, file)| {
            let owner: Box<str> = path.into();
            bodies(file)
                .into_vec()
                .into_iter()
                .map(move |body| (owner.clone(), body))
        })
        .collect()
}

/// Every body shape wide enough to be a duplicate, and every site that states it.
///
/// Name-independent: a copied body renamed on arrival is still one
/// implementation in two places, and it is the copy a later fix reaches only one
/// of. The shape is borrowed as the key rather than moved, because the reading
/// is shared with whatever else the caller asks of the same bodies.
///
/// A caller reads the map twice: the entries holding more than one site are the
/// duplicates, and the size of the map is what says the scan reached anything at
/// all.
pub(crate) fn duplicate_sites(all: &[(Box<str>, Body)]) -> BTreeMap<&str, Vec<String>> {
    let mut sites: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (path, body) in all
        .iter()
        .filter(|(_, body)| body.statements >= MIN_DUPLICATE_STATEMENTS)
    {
        sites
            .entry(&*body.shape)
            .or_default()
            .push(format!("{path}::{}", body.name));
    }
    sites
}

#[derive(Default)]
struct BodyCollector {
    found: Vec<Body>,
}

impl BodyCollector {
    fn record(&mut self, name: &syn::Ident, block: &syn::Block) {
        self.found.push(Body {
            name: name.to_string().into_boxed_str(),
            statements: block.stmts.len(),
            nesting: nesting_depth(block),
            shape: normalized(block),
        });
    }
}

impl<'ast> Visit<'ast> for BodyCollector {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.record(&node.sig.ident, &node.block);
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.record(&node.sig.ident, &node.block);
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        if let Some(block) = &node.default {
            self.record(&node.sig.ident, block);
        }
        syn::visit::visit_trait_item_fn(self, node);
    }
}

/// One body's tokens with every run of whitespace collapsed.
///
/// Formatting is not identity: two copies of one body that differ by a line
/// break are the same duplicate, and the token stream already discards comments.
fn normalized(block: &syn::Block) -> Box<str> {
    block
        .to_token_stream()
        .to_string()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
        .into_boxed_str()
}
