//! Where one page of a paged query continues, and what that claim is bound to.
//!
//! A cursor is opaque on purpose. What a caller holds is the binding a query
//! sealed plus the offset it continues at, and the only thing a caller can do
//! with it is hand it back. Changing any byte — the offset included — produces
//! a token no query minted, and every operation compares the token it was given
//! with the one this state and this request would mint before it reads a
//! record.

use serde::{Deserialize, Serialize};

use crate::index::{CursorBinding, Hex};

/// Where the binding ends and the offset begins.
///
/// Written as the digest's own shape rather than as a bare number, and checked
/// against [`CursorBinding::claimed`] by the annotation in [`PageCursor::minted`]
/// below: a digest that changed width stops compiling there rather than panicking
/// inside a `copy_from_slice` the first time a page is asked for.
const OFFSET_AT: usize = size_of::<[u8; 32]>();

/// The bytes one cursor carries: its sealed binding, then its offset.
const CURSOR_BYTES: usize = OFFSET_AT + size_of::<u32>();

/// Where one page of a paged query continues.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PageCursor {
    token: Hex<CURSOR_BYTES>,
}

impl PageCursor {
    /// The cursor `binding` states for a page starting at `offset`.
    ///
    /// The digest is bound to a width rather than taken as a slice: that is what
    /// makes [`OFFSET_AT`] a claim the compiler checks, and it is the one place
    /// the two widths meet.
    pub(super) fn minted(binding: CursorBinding, offset: u32) -> Self {
        let claimed: [u8; OFFSET_AT] = binding.claimed();
        let mut token = [0_u8; CURSOR_BYTES];
        token[..OFFSET_AT].copy_from_slice(&claimed);
        token[OFFSET_AT..].copy_from_slice(&offset.to_be_bytes());
        Self {
            token: Hex::of(token),
        }
    }

    /// The offset this cursor continues at.
    pub(super) fn offset(self) -> u32 {
        let mut offset = [0_u8; size_of::<u32>()];
        offset.copy_from_slice(&self.token.bytes()[OFFSET_AT..]);
        u32::from_be_bytes(offset)
    }

    /// Whether `binding` is the one that minted this cursor at its own offset.
    pub(super) fn continues(self, binding: CursorBinding) -> bool {
        self == Self::minted(binding, self.offset())
    }
}
