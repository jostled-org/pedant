//! The stack of open contexts one walk carries.
//!
//! Its own owner rather than two locals inside the walk, so the walk holds one
//! insertion site — the fact one — and this bookkeeping cannot be mistaken for
//! retaining a fact.

use crate::go::context::FactContext;
use crate::tree_sitter::Node;

/// One open context and the node that opened it.
struct Frame {
    node: usize,
    context: FactContext,
}

/// Every context the walk currently stands inside.
pub(super) struct Frames(Vec<Frame>);

impl Frames {
    /// A stack holding nothing, which reads as the file context.
    pub(super) fn new() -> Self {
        Self(Vec::new())
    }

    /// The context the walk is standing in.
    ///
    /// An empty stack is the file context: the root opens the file scope, whose
    /// index is always zero because it is the first fact retained.
    pub(super) fn context(&self) -> FactContext {
        self.0
            .last()
            .map(|frame| frame.context)
            .unwrap_or(FactContext::at_file(0))
    }

    /// Open `next` for the children of `node`, unless it changes nothing.
    ///
    /// A frame per real change rather than one per node, so the stack stays as
    /// deep as the nesting that matters rather than as deep as the tree.
    pub(super) fn open(&mut self, node: Node<'_>, context: FactContext, next: FactContext) {
        if next == context {
            return;
        }
        self.0.push(Frame {
            node: node.id(),
            context: next,
        });
    }

    /// Close the context `node` opened, if it opened one.
    pub(super) fn close(&mut self, node: Node<'_>) {
        let opened = self.0.last().is_some_and(|frame| frame.node == node.id());
        if opened {
            self.0.pop();
        }
    }
}
