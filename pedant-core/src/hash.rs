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

fn update_hash_entry(hasher: &mut Sha256, path: &str, content: &str) {
    let path_bytes = path.as_bytes();
    let content_bytes = content.as_bytes();

    hasher.update((path_bytes.len() as u64).to_be_bytes());
    hasher.update(path_bytes);
    hasher.update((content_bytes.len() as u64).to_be_bytes());
    hasher.update(content_bytes);
}

fn encode_hex_digest(digest: &[u8]) -> Box<str> {
    let mut hex: String = String::with_capacity(64);
    for byte in digest {
        // write! to String is infallible; the Result is always Ok
        write!(hex, "{byte:02x}").ok();
    }
    Box::from(hex)
}
