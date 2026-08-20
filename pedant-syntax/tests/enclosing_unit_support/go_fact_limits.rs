//! What a lowered Go fact ceiling refuses, and when it refuses it.
//!
//! A submodule of `tests/enclosing_unit.rs`, reached through a `#[path]`
//! attribute. It shares [`go_facts`](crate::go_facts)'s fixture and its one
//! extraction helper, because a ceiling is only meaningful against the same
//! inventory the completeness case reads.

use pedant_syntax::go::{GoFactError, GoFactLimits};

use crate::go_facts::{FACT_SOURCE, complete_facts, facts};

/// A source with `depth` nested blocks inside one function.
fn nested_source(depth: usize) -> String {
    let mut source = String::from("package widget\n\nfunc build() {\n");
    for _ in 0..depth {
        source.push_str("{\n");
    }
    source.push_str("_ = 1\n");
    for _ in 0..depth {
        source.push_str("}\n");
    }
    source.push_str("}\n");
    source
}

/// 2.T2 (Invariant 5): a lowered ceiling refuses before descent or insertion,
/// and publishes no partial inventory.
#[test]
fn go_fact_limits_refuse_before_descent_or_insertion() {
    let deep = nested_source(24);
    let reached =
        facts(&deep, GoFactLimits::UNBOUNDED).expect("an unbounded inventory of the nested source");
    let depth_limit = 6;
    assert!(
        reached.scopes().len() > depth_limit,
        "the nested source is deeper than the ceiling under test"
    );

    assert_eq!(
        facts(
            &deep,
            GoFactLimits::new(
                u32::try_from(depth_limit).expect("a small ceiling"),
                u32::MAX
            )
        ),
        Err(GoFactError::SyntaxDepthExceeded {
            limit: u32::try_from(depth_limit).expect("a small ceiling")
        }),
        "descent past the syntax-depth ceiling refuses"
    );

    let complete = complete_facts();
    let total = u32::try_from(
        complete.build_conditions().len()
            + complete.imports().len()
            + complete.declarations().len()
            + complete.references().len()
            + complete.scopes().len()
            + complete.bindings().len()
            + 1,
    )
    .expect("a small inventory");
    assert!(total > 1, "the complete source states more than one fact");

    for limit in [0, 1, total / 2, total - 1] {
        assert_eq!(
            facts(FACT_SOURCE, GoFactLimits::new(u32::MAX, limit)),
            Err(GoFactError::FactCapacityExceeded { limit }),
            "a ceiling of {limit} facts refuses before the inventory exceeds it"
        );
    }

    assert!(
        facts(FACT_SOURCE, GoFactLimits::new(u32::MAX, total)).is_ok(),
        "the exact fact count is admitted"
    );
}
