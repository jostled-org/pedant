//! Builder-scoped provenance for records that have no identifier yet.
//!
//! A report's identifiers are assigned by `finish`, after sorting, so a writer
//! needs some other way to point at a record it already added. Two builders can
//! both issue local index zero, so the index alone would let a handle from one
//! builder silently name a different record in another. Each builder owns one
//! zero-sized brand behind an `Arc`, and every handle carries a clone of it:
//! pointer identity gives provenance without a global counter, without
//! process-local state in the serialized report, and without a panic path.

use std::marker::PhantomData;
use std::sync::Arc;

use super::record::ResolutionCertainty;

/// One builder's identity. Zero-sized: only the allocation address matters.
#[derive(Debug)]
pub(crate) struct BuilderBrand;

/// A local insertion index plus the brand and record kind that issued it.
#[derive(Clone, Debug)]
pub struct Handle<K> {
    brand: Arc<BuilderBrand>,
    index: u32,
    kind: PhantomData<fn() -> K>,
}

impl<K> Handle<K> {
    pub(crate) fn new(brand: &Arc<BuilderBrand>, index: u32) -> Self {
        Self {
            brand: Arc::clone(brand),
            index,
            kind: PhantomData,
        }
    }

    /// The local index, if `brand` is the builder that issued this handle.
    pub(crate) fn resolve(&self, brand: &Arc<BuilderBrand>) -> Option<u32> {
        Arc::ptr_eq(&self.brand, brand).then_some(self.index)
    }
}

/// Marker distinguishing unit handles from the other handle kinds.
#[derive(Clone, Debug)]
pub struct UnitHandleKind;

/// Marker distinguishing definition handles from the other handle kinds.
#[derive(Clone, Debug)]
pub struct DefinitionHandleKind;

/// Marker distinguishing reference handles from the other handle kinds.
#[derive(Clone, Debug)]
pub struct ReferenceHandleKind;

/// A unit a builder holds. Clone, never `Copy`, and never serialized.
pub type ResolutionUnitHandle = Handle<UnitHandleKind>;

/// A definition a builder holds. Clone, never `Copy`, and never serialized.
pub type DefinitionHandle = Handle<DefinitionHandleKind>;

/// A reference a builder holds. Clone, never `Copy`, and never serialized.
pub type ReferenceHandle = Handle<ReferenceHandleKind>;

/// One candidate a writer offers for a reference.
///
/// The only way to name a candidate, so a candidate cannot reach a report
/// without passing the same brand check every other handle does.
#[derive(Clone, Debug)]
pub struct CandidateInput {
    definition: DefinitionHandle,
    certainty: ResolutionCertainty,
}

impl CandidateInput {
    /// A candidate definition and how much it is known.
    pub fn new(definition: DefinitionHandle, certainty: ResolutionCertainty) -> Self {
        Self {
            definition,
            certainty,
        }
    }

    /// The handle and its certainty, consuming the input.
    ///
    /// By value because the builder takes the stated candidates by value: a
    /// borrowing accessor would leave the boxed slice owned but never moved.
    pub(crate) fn into_parts(self) -> (DefinitionHandle, ResolutionCertainty) {
        (self.definition, self.certainty)
    }
}
