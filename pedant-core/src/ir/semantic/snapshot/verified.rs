//! Values retained after a resolution snapshot is verified.

use super::prelude::*;

pub(crate) struct VerifiedSource {
    pub(crate) path: Arc<str>,
    pub(crate) absolute: Box<str>,
}

pub(crate) struct VerifiedUnit {
    pub(super) krate: Crate,
    pub(crate) sources: Box<[VerifiedSource]>,
}

impl VerifiedUnit {
    pub(in crate::ir::semantic) fn krate(&self) -> Crate {
        self.krate
    }
}

pub(crate) struct VerifiedSnapshot {
    pub(crate) fingerprint: [u8; 32],
    pub(crate) units: Box<[VerifiedUnit]>,
}
