use std::collections::BTreeMap;
use std::fmt::Write;

use sha2::{Digest, Sha256};

/// SHA-256 digest of source paths and contents, iterated in key order.
///
/// The `BTreeMap` guarantees deterministic iteration regardless of insertion order.
pub fn compute_source_hash<K: Ord + AsRef<str>, V: AsRef<str>>(
    sources: &BTreeMap<K, V>,
) -> Box<str> {
    let mut hasher = Sha256::new();
    for (path, content) in sources {
        update_hash_entry(&mut hasher, path.as_ref(), content.as_ref());
    }
    let digest = hasher.finalize();
    encode_hex_digest(&digest)
}

/// The raw SHA-256 digest of one byte run.
///
/// Kept beside [`compute_source_hash`] because both answer the same question
/// about bytes; the difference is only whether the caller wants the digest or
/// its rendering. Manifest freshness and semantic-snapshot verification both
/// compare digests rather than hex, so they read this one.
pub fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn update_hash_entry(hasher: &mut Sha256, path: &str, content: &str) {
    let path_bytes = path.as_bytes();
    let content_bytes = content.as_bytes();

    hasher.update((path_bytes.len() as u64).to_be_bytes());
    hasher.update(path_bytes);
    hasher.update((content_bytes.len() as u64).to_be_bytes());
    hasher.update(content_bytes);
}

/// Lowercase hex encoding of a digest's bytes.
pub fn encode_hex_digest(digest: &[u8]) -> Box<str> {
    let mut hex: String = String::with_capacity(64);
    for byte in digest {
        // write! to String is infallible; the Result is always Ok
        write!(hex, "{byte:02x}").ok();
    }
    Box::from(hex)
}
