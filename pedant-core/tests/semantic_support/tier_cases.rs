//! The analysis tier a run reports, and what it requires to report it.
use pedant_core::check_config::CheckConfig;
use pedant_core::ir::DataFlowKind;
use pedant_core::ir::{DataFlowFact, IrSpan};
use pedant_core::lint::{analyze, determine_analysis_tier};
use pedant_types::{AnalysisTier, Capability};

use crate::fixtures::{dataflow_lib_path, dataflow_source, dataflow_workspace_root};

/// 5.T4: analysis tier is DataFlow when semantic context produces data flows.
#[test]
fn test_attestation_tier_dataflow() {
    let root = dataflow_workspace_root();
    let ctx =
        crate::fixtures::load_semantic_context(&root).expect("dataflow workspace should load");
    let file_path = dataflow_lib_path();
    let source = dataflow_source();
    let config = CheckConfig::default();

    let result = analyze(&file_path, &source, &config, Some(&ctx)).unwrap();
    let tier = determine_analysis_tier(Some(&ctx), &result.data_flows);

    assert_eq!(
        tier,
        AnalysisTier::DataFlow,
        "tier should be DataFlow when semantic context is active and flows are detected"
    );

    // Without semantic: Syntactic tier
    let plain = analyze(&file_path, &source, &config, None).unwrap();
    let plain_tier = determine_analysis_tier(None, &plain.data_flows);
    assert_eq!(plain_tier, AnalysisTier::Syntactic);

    // Semantic but no flows: Semantic tier
    let semantic_no_flow_tier = determine_analysis_tier(Some(&ctx), &[]);
    assert_eq!(semantic_no_flow_tier, AnalysisTier::Semantic);
}

#[test]
fn test_analysis_tier_requires_semantic_context_for_dataflow() {
    let data_flows = [DataFlowFact {
        kind: DataFlowKind::DiscardedResult,
        source_capability: Some(Capability::FileRead),
        source_span: IrSpan { line: 1, column: 1 },
        sink_capability: Some(Capability::Network),
        sink_span: IrSpan { line: 2, column: 1 },
        call_chain: Box::new([]),
        message: Box::from("synthetic flow"),
    }];

    let tier = determine_analysis_tier(None, &data_flows);
    assert_eq!(tier, AnalysisTier::Syntactic);
}
