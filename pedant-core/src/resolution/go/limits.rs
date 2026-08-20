//! Resource ceilings shared by Go project loading, snapshots, and resolution.

/// Explicit bounds on everything a Go project, snapshot, or resolution may
/// traverse.
///
/// Every field has a documented default. A caller may lower a value to prove a
/// bound, or raise one for a large repository; nothing is truncated silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoResolutionLimits {
    /// Module manifests one project may read. Default 1,024.
    ///
    /// A Go project reads one `go.mod` per admitted module, and a module enters
    /// only through a required local replacement, so this bounds the module
    /// graph rather than the source tree.
    pub max_module_manifests: u32,
    /// Directory entries one snapshot may visit while discovering packages.
    /// Default 65,536.
    pub max_directory_entries: u32,
    /// Resolution units one snapshot may hold. Default 4,096.
    pub max_units: u32,
    /// Distinct source files one snapshot may hold. Default 65,536.
    pub max_source_files: u32,
    /// Bytes one source file may hold. Default 8 MiB.
    pub max_source_file_bytes: u64,
    /// Bytes all distinct source text may hold. Default 512 MiB.
    pub max_total_source_bytes: u64,
    /// Local replacement hops followed from the main module. Default 64.
    ///
    /// The main module sits at depth zero, so a ceiling of zero admits it and
    /// refuses the first replacement it requires.
    pub max_dependency_depth: u32,
    /// Syntax nesting depth accepted while extracting Go facts. Default 256.
    pub max_syntax_depth: u32,
    /// Grammar facts one source may yield. Default 262,144.
    pub max_facts_per_source: u32,
    /// Candidates one reference may carry. Default 1,024.
    pub max_candidates_per_reference: u32,
    /// Concrete-type-to-interface comparisons one resolution may make.
    /// Default 1,048,576.
    pub max_interface_comparisons: u32,
}

impl Default for GoResolutionLimits {
    fn default() -> Self {
        Self {
            max_module_manifests: 1_024,
            max_directory_entries: 65_536,
            max_units: 4_096,
            max_source_files: 65_536,
            max_source_file_bytes: 8 * 1_024 * 1_024,
            max_total_source_bytes: 512 * 1_024 * 1_024,
            max_dependency_depth: 64,
            max_syntax_depth: 256,
            max_facts_per_source: 262_144,
            max_candidates_per_reference: 1_024,
            max_interface_comparisons: 1_048_576,
        }
    }
}
