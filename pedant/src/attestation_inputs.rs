//! Validated identifiers required to emit one capability attestation.

/// Source hash, crate name, and crate version after CLI validation.
pub(crate) type AttestationInputs = (Box<str>, Box<str>, Box<str>);
