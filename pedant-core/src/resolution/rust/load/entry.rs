//! Entry-point record produced by automatic Cargo target discovery.

use std::path::PathBuf;

/// One automatically discovered entry point: its target name and its path.
pub(super) type ScannedEntry = (Box<str>, PathBuf);
