//! Which function bodies one Go production source declares, and how each is
//! shaped.
//!
//! One walk, three measures: how many statements a body states, how deeply it
//! nests, and what its tokens are. The third is what makes a duplicate visible
//! across two modules, which no single-file reading can be.

use quote::ToTokens;
use syn::visit::Visit;

use crate::resolution::go::policy_nesting::nesting_depth;

/// One function body a Go production source declares.
pub struct Body {
    /// The function's name, as a failure would report it.
    pub name: Box<str>,
    /// How many statements the body states at its own level.
    pub statements: usize,
    /// The deepest control-flow nesting the body reaches.
    pub nesting: usize,
    /// The body's tokens, whitespace-normalized, so two copies compare equal.
    pub shape: Box<str>,
}

/// Every function body one source declares, free, inherent, or defaulted.
pub fn bodies(file: &syn::File) -> Box<[Body]> {
    let mut collector = BodyCollector::default();
    collector.visit_file(file);
    collector.found.into_boxed_slice()
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
