//! How deeply one production body nests its control flow.
//!
//! An indentation count is not the answer: a body can be shallow on the page
//! and three decisions deep in the tree, and a `#[rustfmt::skip]` block would
//! make the two disagree outright. The tree is what a reader has to hold.

use syn::visit::Visit;

/// The deepest control-flow nesting one production body may reach.
///
/// Two, matching `.pedant.toml`'s `max_depth`. A third layer is where a body
/// stops being readable as one decision and starts being a decision inside a
/// decision inside a loop.
pub(crate) const MAX_NESTING: usize = 2;

/// The deepest control-flow nesting one block reaches.
pub(crate) fn nesting_depth(block: &syn::Block) -> usize {
    let mut nesting = Nesting::default();
    nesting.visit_block(block);
    nesting.deepest
}

/// The deepest control-flow nesting inside one body.
///
/// A closure and a nested item function each start over, because each is its own
/// body and the reader reads it as one. Everything else — a branch, a match, and
/// the three loop forms — is a layer the reader has to hold.
#[derive(Default)]
struct Nesting {
    depth: usize,
    deepest: usize,
}

impl Nesting {
    fn enter(&mut self) {
        self.depth += 1;
        self.deepest = self.deepest.max(self.depth);
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }
}

impl<'ast> Visit<'ast> for Nesting {
    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.enter();
        syn::visit::visit_expr_if(self, node);
        self.leave();
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        self.enter();
        syn::visit::visit_expr_match(self, node);
        self.leave();
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.enter();
        syn::visit::visit_expr_loop(self, node);
        self.leave();
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        self.enter();
        syn::visit::visit_expr_while(self, node);
        self.leave();
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.enter();
        syn::visit::visit_expr_for_loop(self, node);
        self.leave();
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        let held = std::mem::replace(&mut self.depth, 0);
        syn::visit::visit_expr_closure(self, node);
        self.depth = held;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let held = std::mem::replace(&mut self.depth, 0);
        syn::visit::visit_item_fn(self, node);
        self.depth = held;
    }
}
