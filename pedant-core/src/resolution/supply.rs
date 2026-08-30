//! The one shape a snapshot asks a source provider for.
//!
//! The published entry points are generic over the provider, and the walks
//! beneath them are not: threading a type parameter through the Rust frame
//! stack, the candidate resolver, and its store, or through the Go unit table,
//! the directory classifier, and its store, would parameterize a dozen modules
//! on a choice that is made once per source read. The blanket implementation
//! below is the whole adapter — it maps whatever error the provider states into
//! the fault vocabulary the asking language speaks, and everything below it
//! talks to one bound.
//!
//! One owner for both languages, because the erasure is the same erasure: the
//! inventory and the fault are the parameters, and nothing else about asking a
//! provider for one record differs between a Rust seam and a Go seam.

use pedant_types::{SourcePath, SourceProvider, SourceRecord};

/// One record request, with the refusal the asking seam speaks.
///
/// `Inventory` is the language owner's fact type; `Fault` is the refusal the
/// seam beneath this bound already publishes. A provider qualifies whenever its
/// own error converts into that refusal, so a caller may bring a provider of
/// its own without naming the reference provider's error type.
pub(crate) trait SourceSupply<Inventory, Fault> {
    /// The record for one normalized path.
    fn supply(&mut self, path: SourcePath<'_>) -> Result<SourceRecord<Inventory>, Fault>;
}

impl<P, Inventory, Fault> SourceSupply<Inventory, Fault> for P
where
    P: SourceProvider<Inventory>,
    P::Error: Into<Fault>,
{
    fn supply(&mut self, path: SourcePath<'_>) -> Result<SourceRecord<Inventory>, Fault> {
        self.source(path).map_err(Into::into)
    }
}
