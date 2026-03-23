use std::fmt;
use std::sync::Arc;

pub use crate::checks::{ViolationType, lookup_rationale};

/// Rationale explaining why a check exists and how to address it.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct CheckRationale {
    /// What problem this check detects.
    pub problem: &'static str,
    /// How to fix code that triggers this check.
    pub fix: &'static str,
    /// When exceptions to this check are acceptable.
    pub exception: &'static str,
    /// Whether this check is particularly relevant for LLM-generated code.
    pub llm_specific: bool,
}

impl fmt::Display for CheckRationale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Problem:      {}", self.problem)?;
        writeln!(f, "Fix:          {}", self.fix)?;
        writeln!(f, "Exception:    {}", self.exception)?;
        write!(f, "LLM-specific: {}", self.llm_specific)
    }
}

impl ViolationType {
    /// Returns the matched pattern for pattern-based violations, or `None`.
    pub fn pattern(&self) -> Option<&str> {
        match self {
            Self::ForbiddenAttribute { pattern }
            | Self::ForbiddenType { pattern }
            | Self::ForbiddenCall { pattern }
            | Self::ForbiddenMacro { pattern } => Some(pattern),
            _ => None,
        }
    }
}

impl fmt::Display for ViolationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code())
    }
}

/// A single violation found during analysis.
#[derive(Debug, Clone)]
pub struct Violation {
    /// What kind of violation this is.
    pub violation_type: ViolationType,
    /// Path to the file containing the violation.
    pub file_path: Arc<str>,
    /// Line number (1-based).
    pub line: usize,
    /// Column number (1-based).
    pub column: usize,
    /// Human-readable description of the violation.
    pub message: Box<str>,
}

impl Violation {
    /// Creates a new violation at the given source location.
    pub fn new(
        violation_type: ViolationType,
        file_path: Arc<str>,
        line: usize,
        column: usize,
        message: impl Into<Box<str>>,
    ) -> Self {
        Self {
            violation_type,
            file_path,
            line,
            column,
            message: message.into(),
        }
    }

    /// Returns the rationale for this violation's check.
    pub fn rationale(&self) -> CheckRationale {
        self.violation_type.rationale()
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}: {}: {}",
            self.file_path, self.line, self.column, self.violation_type, self.message
        )
    }
}
