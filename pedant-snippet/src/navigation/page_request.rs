//! Which page of a paged result a caller wants.

use serde::{Deserialize, Serialize};

use super::cursor::PageCursor;

/// Which page of a paged result a caller wants.
///
/// An omitted size is the host default, and an omitted cursor is the first
/// page. Both are stated as absence rather than as a sentinel, so a request
/// that means "the beginning" cannot be spelled two ways.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageRequest {
    /// How many items the page carries, defaulting to fifty.
    #[serde(default)]
    pub size: Option<u32>,
    /// Where the page continues, absent for the first one.
    #[serde(default)]
    pub cursor: Option<PageCursor>,
}
