use std::collections::BTreeMap;
use std::fmt::Write;

use sha2::{Digest, Sha256};

/// Compute a SHA-256 hash of all source contents in key order.
///
/// The `BTreeMap` guarantees deterministic iteration regardless of insertion order.
/// Returns a hex-encoded digest.
pub fn compute_source_hash<K: Ord + AsRef<str>, V: AsRef<str>>(
    sources: &BTreeMap<K, V>,
) -> Box<str> {
    let mut hasher = Sha256::new();
    for content in sources.values() {
        hasher.update(content.as_ref().as_bytes());
    }
    let digest = hasher.finalize();
    let mut hex: String = String::with_capacity(64);
    for b in &digest {
        // write! to String is infallible; the Result is always Ok
        write!(hex, "{b:02x}").ok();
    }
    Box::from(hex)
}
