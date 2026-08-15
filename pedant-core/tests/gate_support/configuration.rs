//! Nested `[gate.module-boundary]` configuration: defaults, widths, the three
//! enablement layers, and the concrete rejection contract.

use pedant_core::check_config::{GateConfig, ModuleBoundaryConfig};
use pedant_core::gate::{GateSeverity, ModuleBoundaryFact, all_module_boundary_rules};

use crate::fixture::{
    MODULE_BOUNDARY_RULE_NAMES, assert_gate_config_rejections, assert_no_verdicts,
    assert_rule_severity, cohesion, component, gate_config, judge, misplaced, rule_names,
};

/// The catalog text every operator surface repeats, in evaluation order.
const CATALOG: &[(&str, GateSeverity, &str, &str)] = &[
    (
        "large-scc",
        GateSeverity::Warn,
        "Cyclic component exceeds the configured member limit",
        "cyclic component exceeds max-scc-members",
    ),
    (
        "boundary-crossing-scc",
        GateSeverity::Deny,
        "Cycle crosses a declared module boundary",
        "cycle crosses declared module partitions",
    ),
    (
        "misplaced-symbol",
        GateSeverity::Warn,
        "Symbol has stronger outgoing affinity to another module",
        "foreign-edge affinity meets the misplaced-symbol threshold",
    ),
    (
        "low-module-cohesion",
        GateSeverity::Warn,
        "Module sends too little selected traffic to itself",
        "internal-edge cohesion is below the configured threshold",
    ),
];

/// Every rejected `[gate]` body and the exact message fragment it owes.
const REJECTIONS: &[(&str, &str)] = &[
    (
        "[module-boundary]\nnope = 1\n",
        "unknown module-boundary field 'nope'",
    ),
    (
        "[module-boundary]\nmax-nodes = \"many\"\n",
        "module-boundary field 'max-nodes' must be an integer",
    ),
    (
        "[module-boundary]\nmax-nodes = 1.5\n",
        "module-boundary field 'max-nodes' must be an integer",
    ),
    (
        "[module-boundary]\nenabled = \"yes\"\n",
        "module-boundary field 'enabled' must be a boolean",
    ),
    (
        "[module-boundary]\nenabled = [true]\n",
        "module-boundary field 'enabled' must be a boolean",
    ),
    (
        "[module-boundary]\nmax-nodes = 4294967296\n",
        "module-boundary field 'max-nodes' must fit in u32",
    ),
    (
        "[module-boundary]\nmax-scc-members = -1\n",
        "module-boundary field 'max-scc-members' must fit in u32",
    ),
    (
        "[module-boundary]\nmisplaced-symbol-min-affinity-percent = 101\n",
        "module-boundary field 'misplaced-symbol-min-affinity-percent' must be 0..=100",
    ),
    (
        "[module-boundary]\nlow-module-cohesion-min-percent = -5\n",
        "module-boundary field 'low-module-cohesion-min-percent' must be 0..=100",
    ),
    (
        "[module-boundary]\nlarge-scc = \"loud\"\n",
        "invalid gate severity 'loud'",
    ),
    (
        "[module-boundary]\nlarge-scc = 3\n",
        "module-boundary rule 'large-scc' must be a boolean or a severity string",
    ),
    (
        "[module-boundary]\nlarge-scc = 1.5\n",
        "module-boundary rule 'large-scc' must be a boolean or a severity string",
    ),
    (
        "[module-boundary]\nunknown-rule = false\n",
        "unknown module-boundary field 'unknown-rule'",
    ),
];

fn assert_defaults(config: &ModuleBoundaryConfig) {
    let enabled: bool = config.enabled();
    let max_nodes: u32 = config.max_nodes();
    let max_references: u32 = config.max_references();
    let max_edges: u32 = config.max_edges();
    let max_selected_edges: u32 = config.max_selected_edges();
    let max_scc_members: u32 = config.max_scc_members();
    let min_foreign_edges: u32 = config.misplaced_symbol_min_foreign_edges();
    let min_affinity: u8 = config.misplaced_symbol_min_affinity_percent();
    let min_outgoing: u32 = config.low_module_cohesion_min_outgoing_edges();
    let min_cohesion: u8 = config.low_module_cohesion_min_percent();

    assert!(enabled, "module-boundary evaluation is on by default");
    assert_eq!(max_nodes, 250_000);
    assert_eq!(max_references, 1_000_000);
    assert_eq!(max_edges, 1_000_000);
    assert_eq!(max_selected_edges, 1_000_000);
    assert_eq!(max_scc_members, 8);
    assert_eq!(min_foreign_edges, 3);
    assert_eq!(min_affinity, 60);
    assert_eq!(min_outgoing, 4);
    assert_eq!(min_cohesion, 50);
}

/// One fact per rule, so a disabled rule is visible as a missing verdict.
fn triggering_facts() -> Box<[ModuleBoundaryFact]> {
    Box::new([component(true, 9, 2), misplaced(3, 5), cohesion(1, 3)])
}

/// The catalog is the sole owner of rule metadata.
fn assert_catalog_is_exact() {
    let rules = all_module_boundary_rules();
    assert_eq!(rules.len(), CATALOG.len(), "the catalog has four entries");
    for (rule, expected) in rules.iter().zip(CATALOG) {
        assert_eq!(
            (
                rule.name,
                rule.default_severity,
                rule.description,
                rule.rationale
            ),
            *expected
        );
    }
    assert_eq!(
        CATALOG.iter().map(|(name, ..)| *name).collect::<Vec<_>>(),
        MODULE_BOUNDARY_RULE_NAMES,
        "the catalog records and the shared name list state one order"
    );
}

/// Every written ceiling and threshold reaches its own field at its own width.
fn assert_written_values_reach_their_fields() {
    let configured = gate_config(
        "[module-boundary]\nmax-nodes = 10\nmax-references = 11\nmax-edges = 12\nmax-selected-edges = 13\nmax-scc-members = 14\nmisplaced-symbol-min-foreign-edges = 15\nmisplaced-symbol-min-affinity-percent = 16\nlow-module-cohesion-min-outgoing-edges = 17\nlow-module-cohesion-min-percent = 18\n",
    );
    let ceilings = &configured.module_boundary;
    assert_eq!(
        (
            ceilings.max_nodes(),
            ceilings.max_references(),
            ceilings.max_edges(),
            ceilings.max_selected_edges(),
            ceilings.max_scc_members(),
            ceilings.misplaced_symbol_min_foreign_edges(),
            ceilings.misplaced_symbol_min_affinity_percent(),
            ceilings.low_module_cohesion_min_outgoing_edges(),
            ceilings.low_module_cohesion_min_percent(),
        ),
        (10, 11, 12, 13, 14, 15, 16, 17, 18)
    );
}

/// One catalog, one validation authority, one evaluator, four rule names.
pub(crate) fn module_boundary_enablement_and_catalog_are_single_authority() {
    assert_catalog_is_exact();
    assert_defaults(&GateConfig::default().module_boundary);
    assert_defaults(&gate_config("enabled = true\n").module_boundary);
    assert_written_values_reach_their_fields();

    // One build of the eleven-label fact set, shared by every row below.
    let facts = triggering_facts();

    assert_eq!(
        rule_names(&judge(facts.clone(), &GateConfig::default())),
        MODULE_BOUNDARY_RULE_NAMES,
        "evaluation emits exactly the catalog names"
    );

    let master_off = gate_config("enabled = false\n");
    assert_no_verdicts(
        &judge(facts.clone(), &master_off),
        "the master switch suppresses module-boundary evaluation",
    );

    let nested_off = gate_config("[module-boundary]\nenabled = false\n");
    assert_no_verdicts(
        &judge(facts.clone(), &nested_off),
        "the nested switch suppresses module-boundary evaluation",
    );

    let rule_off = gate_config("[module-boundary]\nlarge-scc = false\nmisplaced-symbol = true\n");
    assert_eq!(
        rule_names(&judge(facts.clone(), &rule_off)),
        [
            "boundary-crossing-scc",
            "misplaced-symbol",
            "low-module-cohesion"
        ],
        "`false` disables one rule and `true` keeps its default"
    );

    let severity_override =
        gate_config("[module-boundary]\nlarge-scc = \"deny\"\nlow-module-cohesion = \"info\"\n");
    let overridden = judge(facts, &severity_override);
    assert_eq!(
        rule_names(&overridden),
        MODULE_BOUNDARY_RULE_NAMES,
        "a severity override moves no rule out of the emitted set"
    );
    assert_rule_severity(&overridden, "large-scc", GateSeverity::Deny);
    assert_rule_severity(&overridden, "low-module-cohesion", GateSeverity::Info);
    assert_rule_severity(&overridden, "boundary-crossing-scc", GateSeverity::Deny);
    assert_rule_severity(&overridden, "misplaced-symbol", GateSeverity::Warn);

    let capability_rule_still_parses = gate_config("build-script-network = \"info\"\n");
    assert!(capability_rule_still_parses.enabled);
    assert_defaults(&capability_rule_still_parses.module_boundary);

    assert_gate_config_rejections(REJECTIONS);
}
