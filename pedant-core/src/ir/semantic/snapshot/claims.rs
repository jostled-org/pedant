//! Resolution snapshot claims presented to semantic verification.

use super::prelude::*;

pub(crate) struct SemanticUnitClaim {
    pub(crate) name: Arc<str>,
    pub(crate) crate_root: Arc<str>,
    pub(crate) sources: Box<[Arc<str>]>,
    pub(crate) conditional: bool,
}

pub(crate) struct SemanticEdgeClaim {
    pub(crate) source: usize,
    pub(crate) target: usize,
    pub(crate) alias: Arc<str>,
    pub(crate) conditional: bool,
}

pub(crate) struct SemanticSourceClaim {
    pub(crate) path: Arc<str>,
    pub(crate) digest: [u8; 32],
}

pub(crate) struct SemanticSnapshotClaim {
    pub(crate) root: Box<Path>,
    pub(crate) requested: usize,
    pub(crate) fingerprint: [u8; 32],
    pub(crate) units: Box<[SemanticUnitClaim]>,
    pub(crate) edges: Box<[SemanticEdgeClaim]>,
    pub(crate) sources: Box<[SemanticSourceClaim]>,
}
