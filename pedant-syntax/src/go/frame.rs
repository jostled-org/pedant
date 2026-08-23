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
pub(super) struct Frames {
    /// What an empty stack reads as: the file scope the walk opened before it
    /// entered its first node.
    base: FactContext,
    open: Vec<Frame>,
}

impl Frames {
    /// A stack holding nothing, based on the file scope `file` names.
    ///
    /// The index is handed in rather than written down. Zero was true only
    /// while nothing could be retained ahead of the file scope, and a fact
    /// recognized at `source_file` would have shifted it to one — silently
    /// rescoping every fact in the file to whatever landed at zero instead.
    pub(super) fn new(file: u32) -> Self {
        Self {
            base: FactContext::at_file(file),
            open: Vec::new(),
        }
    }

    /// The context the walk is standing in.
    pub(super) fn context(&self) -> FactContext {
        self.open
            .last()
            .map(|frame| frame.context)
            .unwrap_or(self.base)
    }

    /// Open `next` for the children of `node`, unless it changes nothing.
    ///
    /// A frame per real change rather than one per node, so the stack stays as
    /// deep as the nesting that matters rather than as deep as the tree.
    pub(super) fn open(&mut self, node: Node<'_>, context: FactContext, next: FactContext) {
        if next == context {
            return;
        }
        self.open.push(Frame {
            node: node.id(),
            context: next,
        });
    }

    /// Close the context `node` opened, if it opened one.
    pub(super) fn close(&mut self, node: Node<'_>) {
        let opened = self
            .open
            .last()
            .is_some_and(|frame| frame.node == node.id());
        if opened {
            self.open.pop();
        }
    }
}
