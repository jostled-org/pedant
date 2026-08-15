//! Gate severity, the verdict record, source anchors, and structured evidence.

use std::fmt;
use std::sync::Arc;

use serde::Serialize;

use super::module_boundary::ModuleBoundaryInputError;

/// Controls whether a gate verdict blocks CI, warns, or is purely informational.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GateSeverity {
    /// Blocks CI/publish with a non-zero exit code.
    Deny,
    /// Displayed but does not affect exit code.
    Warn,
    /// Logged for audit trail; no user-facing output by default.
    Info,
}

impl fmt::Display for GateSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deny => f.write_str("deny"),
            Self::Warn => f.write_str("warn"),
            Self::Info => f.write_str("info"),
        }
    }
}

/// What a location was derived from, which decides annotation precedence.
///
/// A file anchor is the whole-file fallback at line 1, column 1. A span that
/// genuinely starts at 1:1 is indistinguishable from it by coordinates, so the
/// derivation is carried rather than inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateAnchor {
    /// The declaration's own source span.
    Span,
    /// The file that holds the declaration, with no span of its own.
    File,
}

/// A one-based, repository-relative source anchor carried by gate evidence.
///
/// The anchor kind is judgment-internal: it selects a component annotation and
/// is not serialized, so the published location object keeps its exact bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GateLocation {
    path: Arc<str>,
    line: u32,
    column: u32,
    #[serde(skip)]
    anchor: GateAnchor,
}

impl GateLocation {
    /// Build a span location, rejecting an empty path and zero coordinates.
    pub fn try_new(
        path: impl Into<Arc<str>>,
        line: u32,
        column: u32,
    ) -> Result<Self, ModuleBoundaryInputError> {
        Self::anchored(path, line, column, GateAnchor::Span)
    }

    /// Build a whole-file location at line 1, column 1, rejecting an empty path.
    pub fn try_new_file(path: impl Into<Arc<str>>) -> Result<Self, ModuleBoundaryInputError> {
        Self::anchored(path, 1, 1, GateAnchor::File)
    }

    fn anchored(
        path: impl Into<Arc<str>>,
        line: u32,
        column: u32,
        anchor: GateAnchor,
    ) -> Result<Self, ModuleBoundaryInputError> {
        let path = path.into();
        match (path.is_empty(), line, column) {
            (true, _, _) => Err(ModuleBoundaryInputError::EmptyLocationPath),
            (false, 0, _) => Err(ModuleBoundaryInputError::ZeroLocationLine),
            (false, _, 0) => Err(ModuleBoundaryInputError::ZeroLocationColumn),
            (false, _, _) => Ok(Self {
                path,
                line,
                column,
                anchor,
            }),
        }
    }

    /// The normalized, repository-relative source path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The one-based line.
    pub fn line(&self) -> u32 {
        self.line
    }

    /// The one-based byte column.
    pub fn column(&self) -> u32 {
        self.column
    }

    /// Whether the coordinates came from a span or from the holding file.
    pub fn anchor(&self) -> GateAnchor {
        self.anchor
    }
}

/// One graph-derived subject, member, or partition, identified without a graph.
///
/// The ordinal is the source node index copied as plain evidence. It keeps two
/// equal qualified labels distinct, including when neither declaration has
/// source bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModuleBoundaryEntity {
    ordinal: u32,
    label: Arc<str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<GateLocation>,
}

impl ModuleBoundaryEntity {
    /// Build an entity, rejecting an empty label.
    pub fn try_new(
        ordinal: u32,
        label: impl Into<Arc<str>>,
        location: Option<GateLocation>,
    ) -> Result<Self, ModuleBoundaryInputError> {
        let label = label.into();
        match label.is_empty() {
            true => Err(ModuleBoundaryInputError::EmptyEntityLabel { ordinal }),
            false => Ok(Self {
                ordinal,
                label,
                location,
            }),
        }
    }

    /// The target-local ordinal that disambiguates equal labels.
    pub fn ordinal(&self) -> u32 {
        self.ordinal
    }

    /// The container-qualified label, joined with `::`.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The source anchor, absent for a declaration without source bytes.
    pub fn location(&self) -> Option<&GateLocation> {
        self.location.as_ref()
    }
}

/// What a module-boundary rule measured, retained exactly as it was judged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ModuleBoundaryMeasurement {
    /// One condensed component and the declared partitions it occupies.
    Component {
        /// Whether the component contains a cycle.
        cyclic: bool,
        /// Component members, in graph-node order.
        members: Arc<[ModuleBoundaryEntity]>,
        /// Declared partitions the members occupy, in graph-node order.
        partitions: Arc<[ModuleBoundaryEntity]>,
    },
    /// One symbol whose outgoing edges favour another declared partition.
    MisplacedSymbol {
        /// The partition that declares the symbol.
        declared_partition: ModuleBoundaryEntity,
        /// The partition its outgoing edges favour.
        candidate_partition: ModuleBoundaryEntity,
        /// Selected outgoing edges that leave the declared partition.
        foreign_edges: u32,
        /// All selected outgoing edges of the symbol.
        total_outgoing_edges: u32,
    },
    /// One module's split between internal and boundary-crossing traffic.
    LowModuleCohesion {
        /// Selected outgoing edges that stay inside the module.
        internal_edges: u32,
        /// Selected outgoing edges that leave the module.
        boundary_edges: u32,
    },
}

/// A module-boundary verdict's target, subject, and measurement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModuleBoundaryEvidence {
    target: Arc<str>,
    subject: ModuleBoundaryEntity,
    measurement: ModuleBoundaryMeasurement,
}

impl ModuleBoundaryEvidence {
    /// Share one input's target label into one triggering fact.
    pub(super) fn new(
        target: Arc<str>,
        subject: ModuleBoundaryEntity,
        measurement: ModuleBoundaryMeasurement,
    ) -> Self {
        Self {
            target,
            subject,
            measurement,
        }
    }

    /// The root target label the judged facts were scoped to.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The entity the verdict names.
    pub fn subject(&self) -> &ModuleBoundaryEntity {
        &self.subject
    }

    /// The counts that triggered the verdict.
    pub fn measurement(&self) -> &ModuleBoundaryMeasurement {
        &self.measurement
    }
}

/// Structured evidence attached to a verdict, tagged by its judgment domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "domain", content = "evidence", rename_all = "snake_case")]
pub enum GateEvidence {
    /// Evidence produced by a module-boundary rule.
    ModuleBoundary(ModuleBoundaryEvidence),
}

/// Produced when a gate rule's predicate matches its input.
#[derive(Debug, Serialize)]
pub struct GateVerdict {
    /// Kebab-case rule identifier (e.g., `"build-script-network"`).
    pub rule: &'static str,
    /// Effective severity after config overrides.
    pub severity: GateSeverity,
    /// Why this input is suspicious.
    pub rationale: &'static str,
    /// Structural detail, absent for capability and data-flow rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<GateEvidence>,
}
