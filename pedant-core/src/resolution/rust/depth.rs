//! Syntax nesting depth of one source text.
//!
//! Depth is counted over the delimiter groups the text lexes into, so string
//! and comment contents cannot inflate it. Lexing answers the question on its
//! own: rendering a parsed file back to tokens would rebuild the whole tree a
//! second time to learn something the token layer already states, and it could
//! only state it after the recursive parse the ceiling exists to keep bounded.
//! The traversal uses an explicit worklist, because a recursive walk would
//! overflow on exactly the deeply nested input the ceiling exists to reject.

use std::str::FromStr;

use proc_macro2::{LexError, TokenStream, TokenTree};

/// The deepest delimiter nesting `text` contains. Top-level tokens are zero.
///
/// Text that does not lex has no depth, and the caller reports it as the
/// invalid Rust it is.
pub(in crate::resolution::rust) fn syntax_depth(text: &str) -> Result<u32, LexError> {
    let mut deepest = 0;
    let mut pending = vec![(TokenStream::from_str(text)?, 0)];
    while let Some((stream, depth)) = pending.pop() {
        deepest = deepest.max(depth);
        pending.extend(nested_groups(stream, depth));
    }
    Ok(deepest)
}

fn nested_groups(stream: TokenStream, depth: u32) -> Vec<(TokenStream, u32)> {
    stream
        .into_iter()
        .filter_map(|tree| match tree {
            TokenTree::Group(group) => Some((group.stream(), depth.saturating_add(1))),
            _ => None,
        })
        .collect()
}
