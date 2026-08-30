//! Reading one closed token back from the text a caller typed.
//!
//! Every closed vocabulary this binary accepts — a match mode, a language, a
//! structure kind, a direction, an edge kind, a certainty, an analysis mode, a
//! revision, a cursor — is already spelled by the library's own serializer.
//! Rather than restate any of those tables here, the text is handed to that same
//! deserializer, so the spelling a caller types is by construction the spelling
//! an answer prints.
//!
//! Restating one would be the whole bug: a command line that accepted `syntax`
//! for a coverage the library writes as `syntax_only` would refuse a value it
//! had just printed, and nothing in either table would say so.

use serde::Deserialize;
use serde::de::IntoDeserializer;
use serde::de::value::{Error, StrDeserializer};

/// The value `text` states, in whichever closed vocabulary `T` owns.
///
/// Used as a `clap` value parser, so the refusal is the serializer's own
/// sentence — which, for a closed enum, enumerates every token it would have
/// accepted.
pub(crate) fn token<T: for<'any> Deserialize<'any>>(text: &str) -> Result<T, Error> {
    let deserializer: StrDeserializer<'_, Error> = text.into_deserializer();
    T::deserialize(deserializer)
}
