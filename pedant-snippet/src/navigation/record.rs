//! What a navigation answer says about one structure and one file.
//!
//! Every record here is owned rather than borrowed, because a response is
//! serialized and sent: a page of two hundred items copies two hundred paths
//! and names, and the index goes on holding the one copy each of them shares.
//!
//! The project list is the exception, and shared rather than copied. Every
//! structure declared in one file states the same list, so a page describes it
//! once and hands each descriptor a refcount on it.

use std::sync::Arc;

use pedant_types::{Language, StructureKind, StructureSpan};
use serde::{Deserialize, Serialize};

use crate::index::{ProjectHandle, StructureCoverage, StructureHandle};

/// What every navigation answer says about one structure.
///
/// Ten independent facts about one structure, written by the one describer that
/// states them. The fields are `pub(super)` so that describer builds the record
/// as a literal: a constructor taking ten positional arguments is ten chances to
/// transpose two of the same type, and outside this module the type stays opaque
/// behind its accessors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructureDescriptor {
    pub(super) handle: StructureHandle,
    pub(super) owner: Option<StructureHandle>,
    pub(super) language: Language,
    pub(super) kind: StructureKind,
    pub(super) name: Option<Box<str>>,
    pub(super) qualified_name: Box<str>,
    pub(super) path: Box<str>,
    pub(super) span: StructureSpan,
    pub(super) coverage: StructureCoverage,
    pub(super) projects: Arc<[ProjectHandle]>,
}

impl StructureDescriptor {
    /// This structure's revision-bound identity.
    pub fn handle(&self) -> StructureHandle {
        self.handle
    }

    /// The nearest indexed structure that lexically owns it.
    pub fn owner(&self) -> Option<StructureHandle> {
        self.owner
    }

    /// The language its source was recognized as.
    pub fn language(&self) -> Language {
        self.language
    }

    /// What it declares.
    pub fn kind(&self) -> StructureKind {
        self.kind
    }

    /// Its declared name, absent where its grammar states none.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Its normalized path, named owner chain, and own name, joined by `::`.
    pub fn qualified_name(&self) -> &str {
        &self.qualified_name
    }

    /// The normalized repository path of the source that declares it.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The extent of the whole declaration in that source.
    pub fn span(&self) -> StructureSpan {
        self.span
    }

    /// How many physical lines that extent covers.
    pub fn line_count(&self) -> u32 {
        self.span.line_count()
    }

    /// What kind of evidence stands behind it.
    pub fn coverage(&self) -> StructureCoverage {
        self.coverage
    }

    /// Every project slice whose corpus reached its source.
    pub fn projects(&self) -> &[ProjectHandle] {
        &self.projects
    }
}

/// One file's complete structure forest, in source order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOutline {
    path: Box<str>,
    language: Language,
    structures: Box<[StructureDescriptor]>,
}

impl FileOutline {
    /// The outline one admitted source states.
    pub(super) fn stated(
        path: Box<str>,
        language: Language,
        structures: Box<[StructureDescriptor]>,
    ) -> Self {
        Self {
            path,
            language,
            structures,
        }
    }

    /// The normalized repository path this outline is of.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The language the source was recognized as.
    pub fn language(&self) -> Language {
        self.language
    }

    /// Every structure it declares, in source order.
    pub fn structures(&self) -> &[StructureDescriptor] {
        &self.structures
    }
}

/// One structure and the exact source its span covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructureSource {
    structure: StructureDescriptor,
    text: Box<str>,
}

impl StructureSource {
    /// One structure, read at its span.
    pub(super) fn stated(structure: StructureDescriptor, text: Box<str>) -> Self {
        Self { structure, text }
    }

    /// What the answer says about the structure.
    pub fn structure(&self) -> &StructureDescriptor {
        &self.structure
    }

    /// The retained source its span covers, byte for byte.
    pub fn text(&self) -> &str {
        &self.text
    }
}
