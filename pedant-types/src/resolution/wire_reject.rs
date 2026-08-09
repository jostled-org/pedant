//! Immediate refusal of one sequence element beyond a report limit.

use serde::Deserializer;
use serde::de::{DeserializeSeed, Error as DeserializeError};

use super::error::ResolutionReportError;

pub(super) struct RejectElement {
    error: ResolutionReportError,
}

impl RejectElement {
    pub(super) fn new(error: ResolutionReportError) -> Self {
        Self { error }
    }
}

impl<'de> DeserializeSeed<'de> for RejectElement {
    type Value = ();

    fn deserialize<D>(self, _: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        Err(D::Error::custom(self.error))
    }
}
