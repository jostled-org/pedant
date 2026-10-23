//! Structural fingerprints: identical bodies hash alike, different shapes do not.
//!
//! A submodule of `tests/ir_extraction.rs`, reached through a `#[path]`
//! attribute and not a test root of its own: this directory carries no
//! `main.rs`, so cargo declares no test executable for it.

use pedant_core::ir::extract::compute_fingerprints;

use super::parse_and_extract;

// ── Step 4/5: Structural fingerprints ───────────────────────────────
// 5.T1: These tests serve as the regression guard for compute_fingerprints
// after rebucketing removal. All outputs must remain identical.

// 4.T1: Identical function bodies produce matching hashes
#[test]
fn test_identical_functions_same_hashes() {
    let source = r#"
        fn alpha(x: i32) -> i32 {
            let a = vec![1, 2, 3];
            if x > 0 {
                a.len() as i32
            } else {
                0
            }
        }

        fn beta(y: i32) -> i32 {
            let b = vec![1, 2, 3];
            if y > 0 {
                b.len() as i32
            } else {
                0
            }
        }
    "#;
    let ir = parse_and_extract(source);
    let fingerprints = compute_fingerprints(&ir);

    assert_eq!(fingerprints.len(), 2);
    let alpha = fingerprints.iter().find(|f| &*f.name == "alpha").unwrap();
    let beta = fingerprints.iter().find(|f| &*f.name == "beta").unwrap();

    assert_eq!(alpha.skeleton_hash, beta.skeleton_hash);
    assert_eq!(alpha.exact_hash, beta.exact_hash);
}

// 4.T2: Same structure, different method names → same skeleton, different exact
#[test]
fn test_parametric_functions_same_skeleton_different_exact() {
    let source = r#"
        struct Ui;
        impl Ui {
            fn panels(&self) -> Vec<i32> { vec![] }
            fn overlays(&self) -> Vec<i32> { vec![] }
        }

        fn render_panels(ui: &Ui) -> usize {
            let items = ui.panels();
            if items.is_empty() {
                return 0;
            }
            items.len()
        }

        fn render_overlays(ui: &Ui) -> usize {
            let items = ui.overlays();
            if items.is_empty() {
                return 0;
            }
            items.len()
        }
    "#;
    let ir = parse_and_extract(source);
    let fingerprints = compute_fingerprints(&ir);

    let panels = fingerprints
        .iter()
        .find(|f| &*f.name == "render_panels")
        .unwrap();
    let overlays = fingerprints
        .iter()
        .find(|f| &*f.name == "render_overlays")
        .unwrap();

    assert_eq!(
        panels.skeleton_hash, overlays.skeleton_hash,
        "skeleton hashes should match for parametric duplicates"
    );
    assert_ne!(
        panels.exact_hash, overlays.exact_hash,
        "exact hashes should differ when method names differ"
    );
}

// 4.T3: Different control flow structure → different skeleton
#[test]
fn test_different_structure_different_skeleton() {
    let source = r#"
        fn with_branch(x: i32) -> i32 {
            if x > 0 {
                match x {
                    1 => 1,
                    _ => 2,
                }
            } else {
                0
            }
        }

        fn with_loop(x: i32) -> i32 {
            let mut sum = 0;
            for i in 0..x {
                sum += i;
            }
            sum
        }
    "#;
    let ir = parse_and_extract(source);
    let fingerprints = compute_fingerprints(&ir);

    let branch = fingerprints
        .iter()
        .find(|f| &*f.name == "with_branch")
        .unwrap();
    let loopy = fingerprints
        .iter()
        .find(|f| &*f.name == "with_loop")
        .unwrap();

    assert_ne!(
        branch.skeleton_hash, loopy.skeleton_hash,
        "different control flow should produce different skeleton hashes"
    );
}

// 4.T4: Trivial getter has low fact count
#[test]
fn test_trivial_functions_low_fact_count() {
    let source = r#"
        struct Config { value: i32 }

        impl Config {
            fn value(&self) -> i32 {
                self.value
            }
        }
    "#;
    let ir = parse_and_extract(source);
    let fingerprints = compute_fingerprints(&ir);

    let getter = fingerprints.iter().find(|f| &*f.name == "value").unwrap();
    assert!(
        getter.fact_count < 3,
        "trivial getter should have low fact_count, got {}",
        getter.fact_count
    );
}
