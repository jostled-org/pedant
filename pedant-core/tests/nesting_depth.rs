//! A closure is a value, not a control-flow nesting level. Combinator chains
//! like `.or_else(|| …).map(|pos| …)` are flat code, so they must not inflate
//! `max-depth`; genuine `if`/`match`/loop nesting still does, including nesting
//! that lives *inside* a closure body.

use pedant_core::check_config::CheckConfig;
use pedant_core::ir::{ControlFlowKind, extract};
use pedant_core::lint::analyze;
use pedant_core::violation::ViolationType;

fn parse_and_extract(source: &str) -> pedant_core::ir::FileIr {
    let syntax = syn::parse_file(source).expect("parse failed");
    extract("test.rs", &syntax, None)
}

fn config_max_depth(max_depth: usize) -> CheckConfig {
    CheckConfig {
        max_depth,
        ..CheckConfig::default()
    }
}

fn max_depth_count(source: &str, max_depth: usize) -> usize {
    analyze("test.rs", source, &config_max_depth(max_depth), None)
        .expect("analyze failed")
        .violations
        .iter()
        .filter(|v| v.violation_type == ViolationType::MaxDepth)
        .count()
}

/// A `match` arm holding a `.or_else(|| … .map(|pos| …))` combinator chain — two
/// stacked closures, no real nesting. At `max_depth = 2` this must be clean;
/// counting the closures would report a phantom depth-3 violation.
#[test]
fn combinator_closures_do_not_add_depth() {
    let source = r#"
        fn body(s: &str) -> &str {
            match s.strip_prefix('[') {
                Some(inner) => inner
                    .strip_suffix(']')
                    .or_else(|| inner.rfind("]:").map(|pos| &inner[..pos]))
                    .unwrap_or(inner),
                None => s,
            }
        }
    "#;
    assert_eq!(
        max_depth_count(source, 2),
        0,
        "a match plus a two-closure combinator chain is depth 1, not 3"
    );
}

/// Three nested `match` expressions are genuine nesting: depth 3 must still trip
/// `max-depth` at limit 2.
#[test]
fn real_match_nesting_still_trips_max_depth() {
    let source = r#"
        fn deep(a: bool, b: bool, c: bool) -> u8 {
            match a {
                true => match b {
                    true => match c { true => 1, false => 2 },
                    false => 3,
                },
                false => 4,
            }
        }
    "#;
    assert_eq!(
        max_depth_count(source, 2),
        1,
        "three nested matches is depth 3 and must exceed limit 2"
    );
}

/// A closure is transparent to depth, but control flow *inside* it is not: the
/// `if` in the closure body sits at depth 1 (the closure adds nothing), so the
/// fact carries depth 1 rather than 2.
#[test]
fn control_flow_inside_closure_counts_from_parent_depth() {
    let ir =
        parse_and_extract("fn f() { let g = |x: i32| { if x > 0 { let _ = x; } }; let _ = g; }");

    let closure = ir
        .control_flow
        .iter()
        .find(|cf| cf.kind == ControlFlowKind::Closure)
        .expect("closure fact present");
    assert_eq!(closure.depth, 0, "a closure does not add a nesting level");

    let inner_if = ir
        .control_flow
        .iter()
        .find(|cf| cf.kind == ControlFlowKind::If)
        .expect("if fact present");
    assert_eq!(
        inner_if.depth, 1,
        "the if inside the closure is depth 1, not 2 — the closure is transparent"
    );
}
