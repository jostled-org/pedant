#![cfg(feature = "semantic")]

use std::path::PathBuf;

use pedant_core::SemanticContext;
use pedant_core::check_config::CheckConfig;
use pedant_core::ir;
use pedant_core::lint::analyze;
use pedant_core::violation::ViolationType;

fn fixture_workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("semantic_workspace")
}

#[test]
fn test_semantic_context_loads_simple_workspace() {
    let root = fixture_workspace_root();
    let ctx = SemanticContext::load(&root);
    assert!(
        ctx.is_some(),
        "SemanticContext::load should succeed for a valid workspace"
    );
}

#[test]
fn test_resolve_type_through_alias() {
    let root = fixture_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
    let lib_path = root.join("src").join("lib.rs");
    let file = lib_path.to_str().expect("path should be valid UTF-8");

    // Line 11 (1-based): `pub fn foo() -> MyArc {`
    // MyArc starts at column 16 (0-based).
    // resolve_type should resolve through the alias to Arc<String>.
    let resolved = ctx.resolve_type(file, 11, 16);
    assert!(
        resolved.is_some(),
        "resolve_type should return Some for a type alias in return position"
    );
    let resolved_str = resolved.unwrap();
    assert!(
        resolved_str.contains("Arc"),
        "resolved type should contain 'Arc', got: {resolved_str}"
    );
}

#[test]
fn test_resolve_type_unknown_position_returns_none() {
    let root = fixture_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
    let lib_path = root.join("src").join("lib.rs");
    let file = lib_path.to_str().expect("path should be valid UTF-8");

    // Line 21 (1-based): `/// A comment line for testing unknown position.`
    // No type at a comment position.
    let resolved = ctx.resolve_type(file, 21, 0);
    assert!(
        resolved.is_none(),
        "resolve_type should return None for a comment position"
    );
}

#[test]
fn test_is_copy_for_primitive() {
    let root = fixture_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
    let _ = ctx;
    assert!(SemanticContext::is_copy("i32"), "i32 should implement Copy");
}

#[test]
fn test_is_copy_for_string() {
    let root = fixture_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
    let _ = ctx;
    assert!(
        !SemanticContext::is_copy("String"),
        "String should not implement Copy"
    );
}

#[test]
fn test_load_missing_workspace_returns_none() {
    let nonexistent = PathBuf::from("/tmp/pedant_test_nonexistent_workspace_dir");
    let ctx = SemanticContext::load(&nonexistent);
    assert!(
        ctx.is_none(),
        "SemanticContext::load should return None for a missing workspace"
    );
}

#[test]
fn test_load_invalid_workspace_returns_none() {
    let tmp = std::env::temp_dir().join("pedant_test_invalid_workspace");
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(tmp.join("Cargo.toml"), "[invalid\nbroken toml").unwrap();

    let ctx = SemanticContext::load(&tmp);
    assert!(
        ctx.is_none(),
        "SemanticContext::load should return None for a malformed workspace"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

// --- Step 2: IR extraction enrichment tests ---

fn fixture_lib_path() -> String {
    fixture_workspace_root()
        .join("src")
        .join("lib.rs")
        .to_string_lossy()
        .into_owned()
}

fn parse_fixture() -> syn::File {
    let lib_path = fixture_workspace_root().join("src").join("lib.rs");
    let source = std::fs::read_to_string(&lib_path).expect("fixture lib.rs should exist");
    syn::parse_file(&source).expect("fixture should parse")
}

#[test]
fn test_extract_with_semantic_resolves_binding_type() {
    let root = fixture_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
    let file_path = fixture_lib_path();
    let syntax = parse_fixture();

    let enriched = ir::extract(&file_path, &syntax, Some(&ctx));

    // Find the binding `h` from `binding_through_alias()`
    let binding = enriched
        .bindings
        .iter()
        .find(|b| &*b.name == "h")
        .expect("should find h binding");

    assert!(
        binding.resolved_type.is_some(),
        "resolved_type should be populated for a typed binding"
    );
    let resolved = binding.resolved_type.as_deref().unwrap();
    assert!(
        resolved.contains("Arc"),
        "resolved type should contain 'Arc', got: {resolved}"
    );
    assert!(
        binding.is_refcounted,
        "is_refcounted should be true for a Handle = Arc<String> binding"
    );
}

#[test]
fn test_extract_without_semantic_leaves_none() {
    let file_path = fixture_lib_path();
    let syntax = parse_fixture();

    let plain = ir::extract(&file_path, &syntax, None);

    let binding = plain
        .bindings
        .iter()
        .find(|b| &*b.name == "h")
        .expect("should find _h binding");

    assert!(
        binding.resolved_type.is_none(),
        "resolved_type should be None without semantic context"
    );
    // Syntactic check misses alias — `Handle` doesn't look like Arc/Rc
    assert!(
        !binding.is_refcounted,
        "is_refcounted should be false without semantic (alias not resolved)"
    );
}

#[test]
fn test_extract_resolves_type_ref() {
    let root = fixture_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
    let file_path = fixture_lib_path();
    let syntax = parse_fixture();

    let enriched = ir::extract(&file_path, &syntax, Some(&ctx));

    // bar() returns MyHashMap — find its return TypeRefFact
    let bar_fn_idx = enriched
        .functions
        .iter()
        .position(|f| &*f.name == "bar")
        .expect("should find bar function");

    let type_ref = enriched
        .type_refs
        .iter()
        .find(|tr| tr.containing_fn == Some(bar_fn_idx) && tr.context == ir::TypeRefContext::Return)
        .expect("should find return type ref for bar()");

    assert!(
        type_ref.is_default_hasher,
        "is_default_hasher should be true (resolved through alias)"
    );
}

#[test]
fn test_extract_resolves_method_receiver() {
    let root = fixture_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
    let file_path = fixture_lib_path();
    let syntax = parse_fixture();

    let enriched = ir::extract(&file_path, &syntax, Some(&ctx));

    // Find clone() call in clone_string_in_loop — receiver is String
    let clone_fn_idx = enriched
        .functions
        .iter()
        .position(|f| &*f.name == "clone_string_in_loop")
        .expect("should find clone_string_in_loop function");

    let clone_call = enriched
        .method_calls
        .iter()
        .find(|mc| &*mc.method_name == "clone" && mc.containing_fn == Some(clone_fn_idx))
        .expect("should find clone method call in clone_string_in_loop");

    assert!(
        clone_call.receiver_type.is_some(),
        "receiver_type should be populated"
    );
    assert!(
        !clone_call.is_copy_receiver,
        "String should not be a Copy receiver"
    );
}

#[test]
fn test_extract_copy_receiver_detected() {
    let root = fixture_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
    let file_path = fixture_lib_path();
    let syntax = parse_fixture();

    let enriched = ir::extract(&file_path, &syntax, Some(&ctx));

    // Find clone() call in clone_copy_in_loop — receiver is i32
    let copy_fn_idx = enriched
        .functions
        .iter()
        .position(|f| &*f.name == "clone_copy_in_loop")
        .expect("should find clone_copy_in_loop function");

    let clone_call = enriched
        .method_calls
        .iter()
        .find(|mc| &*mc.method_name == "clone" && mc.containing_fn == Some(copy_fn_idx))
        .expect("should find clone method call in clone_copy_in_loop");

    assert!(
        clone_call.is_copy_receiver,
        "i32 should be detected as a Copy receiver"
    );
}

// --- Step 3: analyze() with SemanticContext ---

fn fixture_source() -> String {
    let lib_path = fixture_workspace_root().join("src").join("lib.rs");
    std::fs::read_to_string(&lib_path).expect("fixture lib.rs should exist")
}

fn clone_in_loop_config() -> CheckConfig {
    CheckConfig {
        check_clone_in_loop: true,
        max_depth: 10,
        forbid_unsafe: false,
        ..CheckConfig::default()
    }
}

fn default_hasher_config() -> CheckConfig {
    CheckConfig {
        check_default_hasher: true,
        max_depth: 10,
        forbid_unsafe: false,
        ..CheckConfig::default()
    }
}

/// 3.T1: With semantic analysis, clone on aliased Arc in a loop is NOT flagged
/// (recognized as refcounted through alias). Without semantic, it IS flagged.
#[test]
fn test_analyze_with_semantic_detects_aliased_refcount() {
    let root = fixture_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
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
    let ctx = SemanticContext::load(&root).expect("workspace should load");
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
    let ctx = SemanticContext::load(&root).expect("workspace should load");
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
    let result = analyze(&file_path, &source, &config, Some(&ctx)).unwrap();
    // No network/filesystem capabilities in the fixture
    assert!(
        result.capabilities.findings.is_empty(),
        "fixture should not trigger capability findings, got: {:?}",
        result.capabilities.findings
    );
}
