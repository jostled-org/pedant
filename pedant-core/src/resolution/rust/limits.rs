//! Resource ceilings shared by project loading and snapshot construction.

/// Explicit bounds on everything a project or snapshot may traverse.
///
/// Every field has a documented default. A caller may lower a value to prove a
/// bound, or raise one for a large repository; nothing is truncated silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolutionLimits {
    /// Manifests one project may read. Default 4,096.
    pub max_manifests: u32,
    /// Directory entries one project may visit while expanding `[workspace]`
    /// member and exclude globs. Default 65,536.
    ///
    /// `max_manifests` bounds what a project reads, not what it walks: a
    /// pattern such as `*/*` accepts every directory as a prefix, so the scan
    /// descends a whole tree — a populated `target/` included — before the
    /// first manifest is read and the manifest ceiling applies.
    pub max_member_scan_entries: u32,
    /// Resolution units one snapshot may hold. Default 4,096.
    pub max_units: u32,
    /// Distinct source files one snapshot may hold. Default 65,536.
    pub max_source_files: u32,
    /// Bytes one source file may hold. Default 8 MiB.
    pub max_source_file_bytes: u64,
    /// Bytes all distinct source text may hold. Default 512 MiB.
    pub max_total_source_bytes: u64,
    /// Rust module nesting depth followed inside one unit. Default 256.
    pub max_module_depth: u32,
    /// Rust module instances one unit may hold. Default 65,536.
    ///
    /// Depth and distinct-source ceilings do not bound this on their own: a
    /// declaration graph that reaches one source through several `#[path]`
    /// alternatives instantiates that source once per route, so a few dozen
    /// files can name millions of instances while every other ceiling holds.
    pub max_module_instances: u32,
    /// Cargo dependency depth followed from the root target. Default 256.
    pub max_dependency_depth: u32,
    /// Syntax nesting depth accepted while parsing. Default 256.
    pub max_syntax_depth: u32,
    /// Candidates one reference may carry. Default 1,024.
    pub max_candidates_per_reference: u32,
}

impl Default for ResolutionLimits {
    fn default() -> Self {
        Self {
            max_manifests: 4_096,
            max_member_scan_entries: 65_536,
            max_units: 4_096,
            max_source_files: 65_536,
            max_source_file_bytes: 8 * 1_024 * 1_024,
            max_total_source_bytes: 512 * 1_024 * 1_024,
            max_module_depth: 256,
            max_module_instances: 65_536,
            max_dependency_depth: 256,
            max_syntax_depth: 256,
            max_candidates_per_reference: 1_024,
        }
    }
}
