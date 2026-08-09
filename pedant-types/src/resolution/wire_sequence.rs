//! Incremental bounded decoding for one report collection.

use std::fmt;
use std::marker::PhantomData;

use serde::de::{DeserializeSeed, Error as DeserializeError, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::error::{ReportCollection, ResolutionReportError};
use super::wire_reject::RejectElement;

/// One seed and visitor that admits at most `limit` values of `T`.
pub(super) struct LimitedSequenceDecoder<T> {
    limit: u32,
    collection: ReportCollection,
    element: PhantomData<fn() -> T>,
}

impl<T> LimitedSequenceDecoder<T> {
    pub(super) fn new(limit: u32, collection: ReportCollection) -> Self {
        Self {
            limit,
            collection,
            element: PhantomData,
        }
    }
}

impl<'de, T> DeserializeSeed<'de> for LimitedSequenceDecoder<T>
where
    T: Deserialize<'de>,
{
    type Value = Box<[T]>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, T> Visitor<'de> for LimitedSequenceDecoder<T>
where
    T: Deserialize<'de>,
{
    type Value = Box<[T]>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded report collection")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        let mut admitted = 0;
        while admitted < self.limit {
            match sequence.next_element()? {
                Some(value) => {
                    values.push(value);
                    admitted += 1;
                }
                None => return Ok(values.into_boxed_slice()),
            }
        }

        let error = capacity_error(self.collection, self.limit);
        let overflow = sequence.next_element_seed(RejectElement::new(error.clone()))?;
        match overflow {
            Some(()) => Err(A::Error::custom(error)),
            None => Ok(values.into_boxed_slice()),
        }
    }
}

fn capacity_error(collection: ReportCollection, limit: u32) -> ResolutionReportError {
    match collection {
        ReportCollection::Units => ResolutionReportError::UnitCapacityExceeded { limit },
        ReportCollection::Definitions => {
            ResolutionReportError::DefinitionCapacityExceeded { limit }
        }
        ReportCollection::References => ResolutionReportError::ReferenceCapacityExceeded { limit },
        ReportCollection::Resolutions => {
            ResolutionReportError::ResolutionCapacityExceeded { limit }
        }
    }
}
