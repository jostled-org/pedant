use std::fmt;
use std::sync::Arc;

pub use crate::checks::{ViolationType, lookup_rationale};

/// Structured explanation of why a check exists, shown by `--explain`.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct CheckRationale {
    /// The code smell or risk this check detects.
    pub problem: &'static str,
    /// Concrete refactoring steps to eliminate the violation.
    pub fix: &'static str,
    /// Situations where suppression is justified.
    pub exception: &'static str,
    /// `true` when the pattern is disproportionately common in LLM output.
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
    /// The glob pattern that triggered this violation, for pattern-based checks only.
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

/// A located style violation with diagnostic message.
#[derive(Debug, Clone)]
pub struct Violation {
    /// Which check produced this violation.
    pub violation_type: ViolationType,
    /// Absolute path of the offending file.
    pub file_path: Arc<str>,
    /// 1-based line number.
    pub line: usize,
    /// 1-based column number.
    pub column: usize,
    /// Diagnostic message describing the specific issue.
    pub message: Box<str>,
}

impl Violation {
    /// Construct a violation at a specific file location.
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

    /// Delegates to the violation type's check rationale.
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
