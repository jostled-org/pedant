//! `analyze` with a semantic context: aliases it resolves, data flows it
//! records, and reachability it annotates.

use pedant_core::check_config::CheckConfig;
use pedant_core::lint::{analyze, analyze_with_build_script};
use pedant_core::violation::ViolationType;
use pedant_types::SymbolAttributionStatus;

use crate::fixtures::{
    clone_in_loop_config, dataflow_lib_path, dataflow_source, dataflow_workspace_root,
    default_hasher_config, fixture_lib_path, fixture_source, fixture_workspace_root,
};

// --- Existing Step 3: analyze() with SemanticContext ---

/// 3.T1: With semantic analysis, clone on aliased Arc in a loop is NOT flagged
/// (recognized as refcounted through alias). Without semantic, it IS flagged.
#[test]
fn test_analyze_with_semantic_detects_aliased_refcount() {
    let root = fixture_workspace_root();
    let ctx = crate::fixtures::load_semantic_context(&root).expect("workspace should load");
    let file_path = fixture_lib_path();
    let source = fixture_source();
    let config = clone_in_loop_config();

    // clone_aliased_arc_in_loop: h.clone() is at line 37 in the fixture
    let aliased_clone_line = 37;

    // With semantic: alias resolved, clone on Arc is cheap — no violation
    let with_semantic = analyze(&file_path, &source, &config, Some(&ctx)).unwrap();
    let has_aliased_clone = with_semantic.violations.iter().any(|v| {
        matches!(v.violation_type, ViolationType::CloneInLoop) && v.line == aliased_clone_line
    });
    assert!(
        !has_aliased_clone,
        "semantic analysis should suppress clone-in-loop for aliased Arc"
    );

    // Without semantic: alias not resolved, flagged as expensive clone
    let without_semantic = analyze(&file_path, &source, &config, None).unwrap();
    let has_aliased_clone = without_semantic.violations.iter().any(|v| {
        matches!(v.violation_type, ViolationType::CloneInLoop) && v.line == aliased_clone_line
    });
    assert!(
        has_aliased_clone,
        "without semantic, clone-in-loop on aliased Arc should be flagged"
    );
}

/// 3.T2: With semantic analysis, default-hasher violation is raised for aliased HashMap.
#[test]
fn test_analyze_with_semantic_detects_aliased_hasher() {
    let root = fixture_workspace_root();
    let ctx = crate::fixtures::load_semantic_context(&root).expect("workspace should load");
    let file_path = fixture_lib_path();
    let source = fixture_source();
    let config = default_hasher_config();

    let result = analyze(&file_path, &source, &config, Some(&ctx)).unwrap();
    let hasher_violations: Vec<_> = result
        .violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::DefaultHasher))
        .collect();
    assert!(
        !hasher_violations.is_empty(),
        "semantic analysis should detect default hasher through MyHashMap alias"
    );
}

/// 3.T3: With semantic analysis, capability detection still works for aliased imports.
#[test]
fn test_analyze_with_semantic_resolves_capability_alias() {
    let root = fixture_workspace_root();
    let semantic_ctx =
        crate::fixtures::load_semantic_context(&root).expect("workspace should load");
    let file_path = fixture_lib_path();
    let source = fixture_source();
    let config = CheckConfig {
        max_depth: 10,
        forbid_unsafe: false,
        ..CheckConfig::default()
    };

    // Verify analyze with semantic context does not break capability detection.
    // The fixture uses std::sync::Arc and std::collections::HashMap —
    // these are stdlib imports, not external capabilities.
    let analysis = analyze(&file_path, &source, &config, Some(&semantic_ctx)).unwrap();
    // No network/filesystem capabilities in the fixture
    assert!(
        analysis.capabilities.profile.findings.is_empty(),
        "fixture should not trigger capability findings, got: {:?}",
        analysis.capabilities.profile.findings
    );
}

// --- Step 5: Extractor populates DataFlow facts and reachability ---

/// 5.T1: analyze() with SemanticContext populates data_flows.
#[test]
fn test_analyze_with_semantic_populates_data_flows() {
    let root = dataflow_workspace_root();
    let ctx =
        crate::fixtures::load_semantic_context(&root).expect("dataflow workspace should load");
    let file_path = dataflow_lib_path();
    let source = dataflow_source();
    let config = CheckConfig::default();

    let result = analyze(&file_path, &source, &config, Some(&ctx)).unwrap();

    let env_to_net = result.data_flows.iter().any(|f| {
        f.source_capability == Some(pedant_types::Capability::EnvAccess)
            && f.sink_capability == Some(pedant_types::Capability::Network)
    });
    assert!(
        env_to_net,
        "should contain EnvAccess→Network data flow from leak_env, got: {:?}",
        result.data_flows
    );
}

/// 5.T2: analyze() with SemanticContext annotates reachability on findings.
#[test]
fn test_analyze_with_semantic_annotates_reachability() {
    let root = dataflow_workspace_root();
    let ctx =
        crate::fixtures::load_semantic_context(&root).expect("dataflow workspace should load");
    let file_path = dataflow_lib_path();
    let source = dataflow_source();
    let config = CheckConfig::default();

    let result = analyze(&file_path, &source, &config, Some(&ctx)).unwrap();

    // All findings should have reachable set (not None) when semantic is active.
    for finding in result.capabilities.profile.findings.iter() {
        assert!(
            finding.reachable.is_some(),
            "finding at line {} should have reachable annotated, got None",
            finding.location.line,
        );
    }

    // reachable_network() is pub — its findings should be reachable.
    // Line 21: TcpStream::connect string literal "127.0.0.1:8080"
    let reachable_finding = result
        .capabilities
        .profile
        .findings
        .iter()
        .find(|f| f.location.line == 21);
    assert!(
        reachable_finding.is_some_and(|f| f.reachable == Some(true)),
        "finding in pub fn reachable_network (line 21) should be reachable"
    );

    // unreachable_private() is private, never called — unreachable.
    // Line 26: TcpStream::connect string literal "127.0.0.1:8080"
    let unreachable_finding = result
        .capabilities
        .profile
        .findings
        .iter()
        .find(|f| f.location.line == 26);
    assert!(
        unreachable_finding.is_some_and(|f| f.reachable == Some(false)),
        "finding in private fn unreachable_private (line 26) should be unreachable"
    );
}

/// 5.T3: analyze() without SemanticContext leaves data_flows empty and reachable None.
#[test]
fn test_analyze_without_semantic_no_data_flows() {
    let file_path = dataflow_lib_path();
    let source = dataflow_source();
    let config = CheckConfig::default();

    let result = analyze(&file_path, &source, &config, None).unwrap();

    assert!(
        result.data_flows.is_empty(),
        "data_flows should be empty without semantic context"
    );
    for finding in result.capabilities.profile.findings.iter() {
        assert!(
            finding.reachable.is_none(),
            "reachable should be None without semantic, got {:?} at line {}",
            finding.reachable,
            finding.location.line,
        );
    }
}

/// 3.T8 (Invariant 12): a symbol profile carries the same reachability value as
/// the flat finding it groups.
#[test]
fn rust_symbol_reachability_matches_flat_findings() {
    let root = dataflow_workspace_root();
    let ctx =
        crate::fixtures::load_semantic_context(&root).expect("dataflow workspace should load");
    let file_path = dataflow_lib_path();
    let source = dataflow_source();

    let analysis = analyze(&file_path, &source, &CheckConfig::default(), Some(&ctx))
        .unwrap()
        .capabilities;

    assert_eq!(
        analysis.symbol_attribution,
        SymbolAttributionStatus::Complete
    );
    assert!(
        !analysis.symbols.is_empty(),
        "the fixture declares callables that own capability evidence"
    );

    for entry in analysis.symbols.iter() {
        for finding in entry.profile.findings.iter() {
            assert!(
                finding.reachable.is_some(),
                "{}: symbol findings carry reachability when semantic is active",
                entry.symbol.name
            );
            assert!(
                analysis.profile.findings.contains(finding),
                "{} at line {} must equal a flat finding, reachability included",
                entry.symbol.name,
                finding.location.line
            );
        }
    }

    assert_reachability_of(&analysis, "reachable_network", Some(true));
    assert_reachability_of(&analysis, "unreachable_private", Some(false));
}

/// Every finding the named callable owns must carry `expected` reachability.
fn assert_reachability_of(
    analysis: &pedant_types::CapabilityAnalysis,
    name: &str,
    expected: Option<bool>,
) {
    let entry = analysis
        .symbols
        .iter()
        .find(|entry| &*entry.symbol.name == name)
        .unwrap_or_else(|| panic!("`{name}` should own a symbol profile"));
    assert!(
        !entry.profile.findings.is_empty(),
        "`{name}` owns at least one finding"
    );
    assert!(
        entry
            .profile
            .findings
            .iter()
            .all(|finding| finding.reachable == expected),
        "`{name}` findings should report reachable={expected:?}, got {:?}",
        entry
            .profile
            .findings
            .iter()
            .map(|finding| finding.reachable)
            .collect::<Vec<_>>()
    );
}

/// 3.T9 (Invariants 12 and 20): merging a source and its build script keeps
/// every flat and symbol occurrence, main-before-build order, exact symbol
/// identity coalescing, hook context, and per-source reachability.
#[test]
fn test_analyze_with_build_script_preserves_semantic_reachability() {
    let root = dataflow_workspace_root();
    let ctx =
        crate::fixtures::load_semantic_context(&root).expect("dataflow workspace should load");
    let file_path = dataflow_lib_path();
    let source = dataflow_source();
    let config = CheckConfig::default();

    let main_only = analyze(&file_path, &source, &config, Some(&ctx))
        .unwrap()
        .capabilities;
    let merged = analyze_with_build_script(
        &file_path,
        &source,
        &config,
        Some(&ctx),
        Some((&file_path, &source)),
    )
    .unwrap()
    .capabilities;

    assert_eq!(
        merged.symbol_attribution,
        SymbolAttributionStatus::Complete,
        "both merged inputs are parsed Rust"
    );

    assert_flat_merge_is_main_then_build(&merged, &main_only);
    assert_symbol_merge_coalesces_exactly(&merged, &main_only);
}

/// Flat findings are the main source's, then the build script's, with nothing
/// deduplicated.
fn assert_flat_merge_is_main_then_build(
    merged: &pedant_types::CapabilityAnalysis,
    main_only: &pedant_types::CapabilityAnalysis,
) {
    let main_count = main_only.profile.findings.len();
    assert!(main_count > 0, "the fixture produces capability findings");
    assert_eq!(
        merged.profile.findings.len(),
        main_count * 2,
        "no occurrence is deduplicated"
    );
    assert_eq!(
        &merged.profile.findings[..main_count],
        &*main_only.profile.findings,
        "main-source findings come first, unchanged"
    );
    assert_build_hook_echo(
        &merged.profile.findings[main_count..],
        &main_only.profile.findings,
    );
}

/// The build script is the same source at the same path, so every symbol
/// identity collides exactly and coalesces into the main operand's position.
fn assert_symbol_merge_coalesces_exactly(
    merged: &pedant_types::CapabilityAnalysis,
    main_only: &pedant_types::CapabilityAnalysis,
) {
    let identities = |analysis: &pedant_types::CapabilityAnalysis| {
        analysis
            .symbols
            .iter()
            .map(|entry| entry.symbol.clone())
            .collect::<Vec<_>>()
    };
    let main_identities = identities(main_only);
    assert!(
        !main_identities.is_empty(),
        "the fixture attributes evidence"
    );
    assert_eq!(
        identities(merged),
        main_identities,
        "an exact identity collision keeps the first profile's position"
    );

    for (merged_entry, main_entry) in merged.symbols.iter().zip(main_only.symbols.iter()) {
        let owned = main_entry.profile.findings.len();
        assert_eq!(
            merged_entry.profile.findings.len(),
            owned * 2,
            "{} keeps both sources' occurrences",
            merged_entry.symbol.name
        );
        assert_eq!(
            &merged_entry.profile.findings[..owned],
            &*main_entry.profile.findings,
            "{} keeps its main-source findings first",
            merged_entry.symbol.name
        );
        assert_build_hook_echo(
            &merged_entry.profile.findings[owned..],
            &main_entry.profile.findings,
        );
    }
}

/// `appended` must be `original` again, differing only by the build-hook
/// execution context — so order, position, evidence, and reachability all hold.
fn assert_build_hook_echo(
    appended: &[pedant_types::CapabilityFinding],
    original: &[pedant_types::CapabilityFinding],
) {
    assert_eq!(appended.len(), original.len());
    for (built, main) in appended.iter().zip(original) {
        assert!(
            built.is_build_hook(),
            "a build-script finding carries the build-hook context"
        );
        assert_eq!(built.capability, main.capability);
        assert_eq!(built.location, main.location);
        assert_eq!(built.evidence, main.evidence);
        assert_eq!(built.origin, main.origin);
        assert_eq!(
            built.reachable, main.reachable,
            "each source keeps the reachability computed for it before the merge"
        );
    }
}
