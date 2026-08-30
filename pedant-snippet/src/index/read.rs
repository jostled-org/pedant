//! One bounded read, and the digest taken over exactly what it read.
//!
//! The ceiling is enforced with a probe rather than by measuring the file
//! first. A size taken before the read is a size that can change before the
//! read finishes, and a file that grew between the two would be admitted whole
//! past a ceiling that had already agreed to it. Reading the ceiling and then
//! one more byte answers the question with the bytes themselves: a probe that
//! finds anything refuses, and the byte it found never joins the buffer.
//!

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;

use sha2::{Digest, Sha256};

use super::error::{
    CapacityCollection, CapacityOwner, CodeIntelligenceError, capacity, first_excess,
};

/// Read one file, refusing before its first byte past `ceiling` is retained.
pub(crate) fn bounded(
    canonical: &Path,
    path: &str,
    ceiling: u64,
) -> Result<Vec<u8>, CodeIntelligenceError> {
    let mut file = File::open(canonical).map_err(|source| unreadable(path, &source))?;
    // The open handle's metadata is only a capacity hint. The probe below is
    // the admission decision, including when the file changes during the read.
    let stated = file.metadata().map_or(0, |stat| stat.len().min(ceiling));
    bounded_reader(
        &mut file,
        path,
        ceiling,
        usize::try_from(stated).unwrap_or(0),
    )
}

/// Read one stream beneath the exact byte ceiling.
fn bounded_reader<Reader: Read>(
    reader: &mut Reader,
    path: &str,
    ceiling: u64,
    reserve: usize,
) -> Result<Vec<u8>, CodeIntelligenceError> {
    let mut bytes = Vec::with_capacity(reserve);
    let mut bounded = reader.take(ceiling);
    bounded
        .read_to_end(&mut bytes)
        .map_err(|source| unreadable(path, &source))?;
    match over_ceiling(&mut bounded.into_inner(), path)? {
        false => Ok(bytes),
        true => Err(capacity(
            CapacityOwner::Repository,
            CapacityCollection::FileBytes,
            first_excess(ceiling),
            ceiling,
        )),
    }
}

/// Whether one byte past the ceiling is there to be read.
///
/// An interrupted probe is retried because it says nothing about whether an
/// excess byte exists.
fn over_ceiling<Reader: Read>(
    file: &mut Reader,
    path: &str,
) -> Result<bool, CodeIntelligenceError> {
    let mut probe = [0_u8; 1];
    loop {
        match file.read(&mut probe) {
            Ok(read) => return Ok(read != 0),
            Err(source) if source.kind() == ErrorKind::Interrupted => continue,
            Err(source) => return Err(unreadable(path, &source)),
        }
    }
}

/// Exercise the bounded reader without a filesystem backend.
#[cfg(feature = "test-support")]
pub fn bounded_reader_for_test<Reader: Read>(
    reader: &mut Reader,
    ceiling: u64,
) -> Result<Vec<u8>, CodeIntelligenceError> {
    bounded_reader(reader, "test-source", ceiling, 0)
}

/// SHA-256 of exactly the bytes that were read.
pub(crate) fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// One I/O failure as this crate's own refusal names it.
fn unreadable(path: &str, source: &std::io::Error) -> CodeIntelligenceError {
    CodeIntelligenceError::SourceRead {
        path: Box::from(path),
        reason: source.to_string().into_boxed_str(),
    }
}
