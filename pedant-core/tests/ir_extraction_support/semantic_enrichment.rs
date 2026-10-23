//! Batched semantic enrichment over the semantic fixture workspace.
//!
//! A submodule of `tests/ir_extraction.rs`, reached through a `#[path]`
//! attribute and not a test root of its own: this directory carries no
//! `main.rs`, so cargo declares no test executable for it.

use std::path::PathBuf;

use pedant_core::SemanticContext;
use pedant_core::ir::{self, TypeRefContext};

fn fixture_workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("semantic_workspace")
}

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

/// 2.T1: Extraction enriches bindings, type refs, and receivers in one batch.
/// File setup occurs exactly once for the extraction pass.
#[test]
fn test_extract_semantic_enrichment_batches_binding_and_type_resolution() {
    let root = fixture_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
    let file_path = fixture_lib_path();
    let syntax = parse_fixture();

    let enriched = ir::extract(&file_path, &syntax, Some(&ctx));

    // Binding type resolution through alias
    let h_binding = enriched
        .bindings
        .iter()
        .find(|b| &*b.name == "h")
        .expect("should find h binding");
    assert!(
        h_binding.resolved_type.is_some(),
        "resolved_type should be populated for a typed binding"
    );
    assert!(
        h_binding.is_refcounted,
        "is_refcounted should be true for Handle = Arc<String>"
    );

    // Type ref classification through alias
    let bar_fn_idx = enriched
        .functions
        .iter()
        .position(|f| &*f.name == "bar")
        .expect("should find bar function");
    let bar_return_ref = enriched
        .type_refs
        .iter()
        .find(|tr| tr.containing_fn == Some(bar_fn_idx) && tr.context == TypeRefContext::Return)
        .expect("should find return type ref for bar()");
    assert!(
        bar_return_ref.is_default_hasher,
        "should detect default hasher through alias"
    );

    // Receiver type resolution
    let clone_fn_idx = enriched
        .functions
        .iter()
        .position(|f| &*f.name == "clone_string_in_loop")
        .expect("should find clone_string_in_loop");
    let clone_call = enriched
        .method_calls
        .iter()
        .find(|mc| &*mc.method_name == "clone" && mc.containing_fn == Some(clone_fn_idx))
        .expect("should find clone method call");
    assert!(
        clone_call.receiver_type.is_some(),
        "receiver_type should be populated"
    );

    // File setup occurs exactly once for the extraction pass
    assert_eq!(
        ctx.file_setup_count(),
        1,
        "extraction should trigger exactly one file setup (batched resolve)"
    );
}

/// 2.T2: Enriched IR matches pre-batch behavior for all enrichment types.
#[test]
fn test_extract_semantic_enrichment_matches_pre_batch_behavior() {
    let root = fixture_workspace_root();
    let ctx = SemanticContext::load(&root).expect("workspace should load");
    let file_path = fixture_lib_path();
    let syntax = parse_fixture();

    let enriched = ir::extract(&file_path, &syntax, Some(&ctx));

    // Binding: Handle resolved to Arc<String>
    let h = enriched
        .bindings
        .iter()
        .find(|b| &*b.name == "h")
        .expect("should find h binding");
    let resolved = h
        .resolved_type
        .as_deref()
        .expect("resolved_type should exist");
    assert!(
        resolved.contains("Arc"),
        "should resolve Handle to Arc<String>, got: {resolved}"
    );
    assert!(h.is_refcounted);

    // Type ref: bar() return is default hasher
    let bar_idx = enriched
        .functions
        .iter()
        .position(|f| &*f.name == "bar")
        .expect("should find bar");
    let bar_ret = enriched
        .type_refs
        .iter()
        .find(|tr| tr.containing_fn == Some(bar_idx) && tr.context == TypeRefContext::Return)
        .expect("should find bar return type ref");
    assert!(bar_ret.is_default_hasher);

    // Receiver: multiple calls on same String binding all resolved
    let s_fn_idx = enriched
        .functions
        .iter()
        .position(|f| &*f.name == "repeated_method_calls_same_binding")
        .expect("should find repeated_method_calls_same_binding");
    let receiver_calls: Vec<_> = enriched
        .method_calls
        .iter()
        .filter(|mc| mc.containing_fn == Some(s_fn_idx) && mc.receiver_type.is_some())
        .collect();
    assert!(
        receiver_calls.len() >= 3,
        "should resolve at least 3 receiver types, got {}",
        receiver_calls.len()
    );
    for mc in &receiver_calls {
        let rt = mc.receiver_type.as_deref().unwrap();
        assert!(
            rt.contains("String"),
            "receiver should be String, got: {rt}"
        );
    }

    // Copy receiver detection
    let copy_fn_idx = enriched
        .functions
        .iter()
        .position(|f| &*f.name == "clone_copy_in_loop")
        .expect("should find clone_copy_in_loop");
    let copy_clone = enriched
        .method_calls
        .iter()
        .find(|mc| &*mc.method_name == "clone" && mc.containing_fn == Some(copy_fn_idx))
        .expect("should find clone call in clone_copy_in_loop");
    assert!(
        copy_clone.is_copy_receiver,
        "i32 should be detected as Copy"
    );
}

/// 2.T3: Taint flow data is preserved through the batched enrichment path.
#[test]
fn test_extract_semantic_enrichment_preserves_taint_flow_output() {
    let dataflow_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("dataflow_workspace");
    let ctx = SemanticContext::load(&dataflow_root).expect("dataflow workspace should load");
    let file_path = dataflow_root
        .join("src")
        .join("lib.rs")
        .to_string_lossy()
        .into_owned();
    let source = std::fs::read_to_string(dataflow_root.join("src").join("lib.rs"))
        .expect("dataflow lib.rs should exist");
    let syntax = syn::parse_file(&source).expect("fixture should parse");

    let enriched = ir::extract(&file_path, &syntax, Some(&ctx));

    let has_taint = enriched.data_flows.iter().any(|f| {
        f.source_capability == Some(pedant_types::Capability::EnvAccess)
            && f.sink_capability == Some(pedant_types::Capability::Network)
    });
    assert!(
        has_taint,
        "should contain EnvAccess→Network taint flow, got: {:?}",
        enriched.data_flows
    );
}
