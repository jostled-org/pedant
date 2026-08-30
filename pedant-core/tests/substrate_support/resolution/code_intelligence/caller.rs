//! A provider written outside the crate that owns the loaders.
//!
//! Its only job is to be somebody else's implementation of the published
//! contract. It answers through the reference provider rather than
//! reimplementing a reader — what is being proved is that the entry point
//! accepts any implementor, not that a second reader agrees with the first —
//! and it carries an error type this crate has never seen, so an entry point
//! that named the reference provider's error instead of converting the caller's
//! would not compile against it.
//!
//! One implementation, both languages. The Rust and Go halves were token
//! identical but for their type names: the same request, the same refusal, the
//! same recording body. The claim each of them makes survives the collapse,
//! because `CallerFault<RustSourceFault>` and `CallerFault<GoSourceFault>` are
//! still types no crate under test declares.
//!
//! The two conversions below stay written out per language. A blanket
//! `From<CallerFault<E>> for E` is not this root's to write — neither `From` nor
//! either owner's error is local — and it is not optional either: both entry
//! points bound their provider's error by `Into` the owning seam's fault, which
//! is the half of the contract these cases exist to exercise. One concrete row
//! per language is the smallest thing that states it.

use pedant_core::resolution::go::GoSourceFault;
use pedant_core::resolution::rust::RustSourceFault;
use pedant_types::{SourcePath, SourceProvider, SourceRecord};

/// One request the caller's provider was handed.
///
/// Retained rather than borrowed, because a refusal outlives the request that
/// caused it and has to be able to name it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    path: Box<str>,
}

impl Request {
    /// The normalized path this request named.
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Why the caller's provider stated no record, and for which request.
///
/// A type of this test's own: the entry point is exercised with an error the
/// crate has never seen, and it carries the caller's own request rather than
/// the reference provider's, so a converted refusal cannot be mistaken for the
/// reference provider's own.
#[derive(Debug)]
pub struct CallerFault<E> {
    request: Request,
    fault: E,
}

impl<E> CallerFault<E> {
    /// The request this refusal answers.
    pub fn request(&self) -> &Request {
        &self.request
    }
}

impl From<CallerFault<RustSourceFault>> for RustSourceFault {
    fn from(refusal: CallerFault<Self>) -> Self {
        refusal.fault
    }
}

impl From<CallerFault<GoSourceFault>> for GoSourceFault {
    fn from(refusal: CallerFault<Self>) -> Self {
        refusal.fault
    }
}

/// A provider of the caller's own, recording every path it was asked for so a
/// case can state exactly what authority the loader handed across the seam.
pub struct RecordingProvider<P> {
    inner: P,
    requested: Vec<Request>,
}

impl<P> RecordingProvider<P> {
    /// A recording provider wrapping one reference provider.
    pub fn new(inner: P) -> Self {
        Self {
            inner,
            requested: Vec::new(),
        }
    }

    /// Every path the loader asked for, in order.
    pub fn requested(&self) -> Box<[Box<str>]> {
        self.requested
            .iter()
            .map(|request| Box::from(request.path()))
            .collect()
    }
}

impl<P, I> SourceProvider<I> for RecordingProvider<P>
where
    P: SourceProvider<I>,
{
    type Error = CallerFault<P::Error>;

    fn source(&mut self, path: SourcePath<'_>) -> Result<SourceRecord<I>, Self::Error> {
        let request = Request {
            path: Box::from(path.as_str()),
        };
        self.requested.push(request.clone());
        self.inner
            .source(path)
            .map_err(|fault| CallerFault { request, fault })
    }
}
