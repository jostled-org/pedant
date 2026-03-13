use std::collections::BTreeMap;
use std::sync::Arc;

use sha2::{Digest, Sha256};

/// Compute a SHA-256 hash of all source contents in key order.
///
/// The `BTreeMap` guarantees deterministic iteration regardless of insertion order.
/// Returns a hex-encoded digest.
pub fn compute_source_hash(sources: &BTreeMap<Arc<str>, Arc<str>>) -> Arc<str> {
    let mut hasher = Sha256::new();
    for content in sources.values() {
        hasher.update(content.as_bytes());
    }
    let digest = hasher.finalize();
    let hex: String = digest.iter().fold(String::with_capacity(64), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    });
    Arc::from(hex)
}
