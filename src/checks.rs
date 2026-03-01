/// Metadata about a single check, used by `--list-checks` and `--explain`.
#[derive(Debug, Clone, Copy)]
pub struct CheckInfo {
    /// Short code string (e.g., `"max-depth"`).
    pub code: &'static str,
    /// One-line description of what the check detects.
    pub description: &'static str,
    /// Category grouping (e.g., `"nesting"`, `"dispatch"`, `"structure"`).
    pub category: &'static str,
    /// Whether this pattern is particularly common in LLM-generated code.
    pub llm_specific: bool,
}

/// All available checks.
pub const ALL_CHECKS: &[CheckInfo] = &[
    CheckInfo {
        code: "max-depth",
        description: "Excessive nesting depth",
        category: "nesting",
        llm_specific: false,
    },
    CheckInfo {
        code: "nested-if",
        description: "If nested inside if",
        category: "nesting",
        llm_specific: false,
    },
    CheckInfo {
        code: "if-in-match",
        description: "If inside match arm",
        category: "nesting",
        llm_specific: false,
    },
    CheckInfo {
        code: "nested-match",
        description: "Match nested inside match",
        category: "nesting",
        llm_specific: false,
    },
    CheckInfo {
        code: "match-in-if",
        description: "Match inside if branch",
        category: "nesting",
        llm_specific: false,
    },
    CheckInfo {
        code: "else-chain",
        description: "Long if/else if chain",
        category: "nesting",
        llm_specific: false,
    },
    CheckInfo {
        code: "forbidden-attribute",
        description: "Forbidden attribute pattern",
        category: "forbid_attributes",
        llm_specific: true,
    },
    CheckInfo {
        code: "forbidden-type",
        description: "Forbidden type pattern",
        category: "forbid_types",
        llm_specific: true,
    },
    CheckInfo {
        code: "forbidden-call",
        description: "Forbidden method call pattern",
        category: "forbid_calls",
        llm_specific: true,
    },
    CheckInfo {
        code: "forbidden-macro",
        description: "Forbidden macro pattern",
        category: "forbid_macros",
        llm_specific: true,
    },
    CheckInfo {
        code: "forbidden-else",
        description: "Use of `else` keyword (style preference)",
        category: "forbid_else",
        llm_specific: false,
    },
    CheckInfo {
        code: "forbidden-unsafe",
        description: "Use of `unsafe` keyword",
        category: "forbid_unsafe",
        llm_specific: false,
    },
    CheckInfo {
        code: "dyn-return",
        description: "Dynamic dispatch in return type (Box<dyn T>, Arc<dyn T>)",
        category: "dispatch",
        llm_specific: true,
    },
    CheckInfo {
        code: "dyn-param",
        description: "Dynamic dispatch in function parameter (&dyn T, Box<dyn T>)",
        category: "dispatch",
        llm_specific: true,
    },
    CheckInfo {
        code: "vec-box-dyn",
        description: "Vec<Box<dyn T>> prevents cache locality and inlining",
        category: "dispatch",
        llm_specific: true,
    },
    CheckInfo {
        code: "dyn-field",
        description: "Dynamic dispatch in struct field (Box<dyn T>, Arc<dyn T>)",
        category: "dispatch",
        llm_specific: true,
    },
    CheckInfo {
        code: "clone-in-loop",
        description: "clone() called inside loop body",
        category: "performance",
        llm_specific: true,
    },
    CheckInfo {
        code: "default-hasher",
        description: "HashMap/HashSet with default SipHash hasher",
        category: "performance",
        llm_specific: true,
    },
    CheckInfo {
        code: "mixed-concerns",
        description: "Disconnected type groups indicate mixed concerns",
        category: "structure",
        llm_specific: true,
    },
    CheckInfo {
        code: "inline-tests",
        description: "Test module embedded in source file",
        category: "structure",
        llm_specific: true,
    },
];
