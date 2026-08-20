//! The names one Go file's import specifications bind.
//!
//! Imports are file-scoped: two files of one package importing the same path
//! hold two bindings, and a name one file aliases is not that name in the
//! other. So this table is built per file and never per package.

use std::collections::BTreeMap;

use pedant_syntax::go::GoImportForm;

use crate::resolution::go::facts::GoSourceFacts;
use crate::resolution::go::import_fact::GoImportRecord;

use super::corpus::Corpus;

/// What one import specification names.
#[derive(Clone, Copy)]
pub(super) struct ImportTarget {
    /// The unit compiling the imported package, absent for a package outside
    /// the snapshot.
    pub(super) unit: Option<usize>,
}

/// Every name one file's imports bind, and every package it pulls names from.
pub(super) struct FileImports<'a> {
    named: BTreeMap<&'a str, ImportTarget>,
    dotted: Box<[ImportTarget]>,
}

impl<'a> FileImports<'a> {
    /// Read one file's import specifications.
    pub(super) fn of(corpus: &Corpus<'a>, facts: &'a GoSourceFacts) -> Self {
        Self {
            named: facts
                .imports()
                .iter()
                .filter_map(|import| {
                    import
                        .local_name()
                        .map(|name| (name, target(corpus, import)))
                })
                .collect(),
            dotted: facts
                .imports()
                .iter()
                .filter(|import| import.form() == GoImportForm::Dot)
                .map(|import| target(corpus, import))
                .collect(),
        }
    }

    /// The package one file-scoped name binds, when an import binds it.
    pub(super) fn named(&self, name: &str) -> Option<ImportTarget> {
        self.named.get(name).copied()
    }

    /// Every package whose names this file pulls into its own scope.
    pub(super) fn dotted(&self) -> &[ImportTarget] {
        &self.dotted
    }
}

/// What one import specification names, joined against the snapshot.
pub(super) fn target(corpus: &Corpus<'_>, import: &GoImportRecord) -> ImportTarget {
    ImportTarget {
        unit: corpus.package(import.path()),
    }
}
