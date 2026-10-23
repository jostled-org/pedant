//! Facts one parse extracts about declarations: functions, visibility, cfg
//! gates, imports, type definitions, modules and the edges between types.
//!
//! A submodule of `tests/ir_extraction.rs`, reached through a `#[path]`
//! attribute and not a test root of its own: this directory carries no
//! `main.rs`, so cargo declares no test executable for it.

use pedant_core::ir::TypeDefKind;

use super::parse_and_extract;

// 1.T1: Function facts
#[test]
fn test_ir_extracts_function_facts() {
    let source = r#"
        unsafe fn danger(x: i32) -> bool { true }
        fn safe(a: String, b: u64) {}
    "#;
    let ir = parse_and_extract(source);

    assert_eq!(ir.functions.len(), 2);

    let danger = &ir.functions[0];
    assert_eq!(&*danger.name, "danger");
    assert!(danger.is_unsafe);
    assert_eq!(danger.params.len(), 1);
    assert_eq!(&*danger.params[0].name, "x");
    assert!(danger.return_type.is_some());
    assert!(!danger.signature_type_names.is_empty());

    let safe = &ir.functions[1];
    assert_eq!(&*safe.name, "safe");
    assert!(!safe.is_unsafe);
    assert_eq!(safe.params.len(), 2);
    assert_eq!(&*safe.params[0].name, "a");
    assert_eq!(&*safe.params[1].name, "b");
}

// 1.T1b: Function body line-count fact
#[test]
fn test_ir_extracts_body_line_count() {
    // Single-line body: open and close brace share a line.
    let single = parse_and_extract("fn one() { let _ = 1; }");
    assert_eq!(single.functions[0].body_line_count, 1);

    // Multi-line body spanning braces inclusively: `{` on line 1, `}` on line 4.
    let multi = parse_and_extract("fn many() {\n    let a = 1;\n    let _ = a;\n}");
    assert_eq!(multi.functions[0].body_line_count, 4);

    // A trait method declaration without a default has no body.
    let decl = parse_and_extract("trait T { fn f(&self); }");
    assert_eq!(decl.functions[0].body_line_count, 0);
}

// 1.T1c: union extraction and free-vs-associated function distinction
#[test]
fn test_ir_extracts_union_and_associated_flag() {
    let source = r#"
        pub union Bytes { a: u32, b: f32 }
        fn free() {}
        struct S;
        impl S { fn method(&self) {} }
        trait T { fn required(&self); fn provided(&self) {} }
    "#;
    let ir = parse_and_extract(source);

    assert!(
        ir.type_defs
            .iter()
            .any(|t| &*t.name == "Bytes" && t.kind == TypeDefKind::Union)
    );

    let associated = |name: &str| {
        ir.functions
            .iter()
            .find(|f| &*f.name == name)
            .unwrap()
            .is_associated
    };
    assert!(!associated("free"));
    assert!(associated("method"));
    assert!(associated("required"));
    assert!(associated("provided"));
}

// 1.T1d: inherent-method linkage and pure-forwarder classification
#[test]
fn test_ir_classifies_inherent_methods_and_forwarders() {
    let source = r#"
        struct S { inner: H }
        impl S {
            fn plain(&self) -> u32 { 1 }
            fn fwd(&self) -> u32 { self.inner.value() }
            fn fwd_try(&self) -> Option<u32> { self.inner.value()? }
            fn fwd_await(&self) -> u32 { self.inner.value().await }
            fn on_self(&self) -> u32 { self.plain() }
            fn mapped(&self) -> u32 { self.inner.value() + 1 }
            fn deep(&self) -> u32 { self.inner.mid.value() }
        }
        impl T for S {
            fn traited(&self) -> u32 { self.inner.value() }
        }
        fn free() -> u32 { 0 }
    "#;
    let ir = parse_and_extract(source);
    let f = |name: &str| ir.functions.iter().find(|f| &*f.name == name).unwrap();

    // Inherent methods are tagged with their type; trait-impl methods and free fns are not.
    assert_eq!(f("plain").inherent_method_of.as_deref(), Some("S"));
    assert_eq!(f("traited").inherent_method_of, None);
    assert_eq!(f("free").inherent_method_of, None);

    // Pure forwarders: exactly `self.<field>.<method>(..)` with optional `?`/`.await`.
    assert!(f("fwd").is_pure_forwarder);
    assert!(f("fwd_try").is_pure_forwarder);
    assert!(f("fwd_await").is_pure_forwarder);

    // Substantive: delegates to self (not a field), maps the result, or chains deeper.
    assert!(!f("plain").is_pure_forwarder);
    assert!(!f("on_self").is_pure_forwarder);
    assert!(!f("mapped").is_pure_forwarder);
    assert!(!f("deep").is_pure_forwarder);
}

// 1.T1e: visibility normalization
#[test]
fn test_ir_extracts_visibility() {
    use pedant_core::ir::Visibility;
    let source = r#"
        struct Priv;
        pub struct Pub;
        pub(crate) struct Crate;
        pub(super) struct Super;
        pub(in crate::a) struct Scoped;
        pub fn free() {}
    "#;
    let ir = parse_and_extract(source);
    let vis = |name: &str| {
        ir.type_defs
            .iter()
            .find(|t| &*t.name == name)
            .map(|t| t.visibility.clone())
    };
    assert_eq!(vis("Priv"), Some(Visibility::Private));
    assert_eq!(vis("Pub"), Some(Visibility::Public));
    assert_eq!(vis("Crate"), Some(Visibility::Crate));
    assert_eq!(vis("Super"), Some(Visibility::Super));
    assert_eq!(
        vis("Scoped"),
        Some(Visibility::Restricted("crate::a".into()))
    );
    assert_eq!(vis("Scoped").unwrap().to_string(), "pub(in crate::a)");

    let free = ir.functions.iter().find(|f| &*f.name == "free").unwrap();
    assert_eq!(free.visibility, Visibility::Public);
}

// 1.T1f: cfg(feature) gate tracking
#[test]
fn test_ir_tracks_cfg_feature_gates() {
    let source = r#"
        fn ungated() {}
        #[cfg(feature = "test-support")]
        fn item_gated() {}
        #[cfg(feature = "test-support")]
        mod gated_mod {
            fn inherits() {}
        }
        #[cfg(test)]
        fn cfg_test_only() {}
    "#;
    let ir = parse_and_extract(source);
    let gates = |name: &str| {
        ir.functions
            .iter()
            .find(|f| &*f.name == name)
            .unwrap()
            .cfg_feature_gates
            .iter()
            .map(|g| g.to_string())
            .collect::<Vec<_>>()
    };
    assert!(gates("ungated").is_empty());
    assert_eq!(gates("item_gated"), vec!["test-support"]);
    assert_eq!(gates("inherits"), vec!["test-support"]);
    // `#[cfg(test)]` is not a feature gate.
    assert!(gates("cfg_test_only").is_empty());
}

// 1.T5: Use path facts
#[test]
fn test_ir_extracts_use_paths() {
    let source = r#"
        use std::net::TcpStream;
        use std::fs::{read, write};
    "#;
    let ir = parse_and_extract(source);

    let paths: Vec<&str> = ir.use_paths.iter().map(|up| &*up.path).collect();
    assert!(paths.contains(&"std::net::TcpStream"));
    assert!(paths.contains(&"std::fs::read"));
    assert!(paths.contains(&"std::fs::write"));
}

// 1.T7: Type defs and impl blocks
#[test]
fn test_ir_extracts_type_defs_and_impls() {
    let source = r#"
        struct Foo {
            bar: Bar,
        }
        enum Color {
            Red,
            Blue,
        }
        trait Drawable {
            fn draw(&self);
        }
        impl Drawable for Foo {
            fn draw(&self) {}
        }
    "#;
    let ir = parse_and_extract(source);

    // Type defs
    assert_eq!(ir.type_defs.len(), 3);
    let type_names: Vec<&str> = ir.type_defs.iter().map(|td| &*td.name).collect();
    assert!(type_names.contains(&"Foo"));
    assert!(type_names.contains(&"Color"));
    assert!(type_names.contains(&"Drawable"));

    let foo_def = ir.type_defs.iter().find(|td| &*td.name == "Foo").unwrap();
    assert_eq!(foo_def.kind, TypeDefKind::Struct);
    // Foo has edge to Bar
    assert!(!foo_def.edges.is_empty());

    let color_def = ir.type_defs.iter().find(|td| &*td.name == "Color").unwrap();
    assert_eq!(color_def.kind, TypeDefKind::Enum);

    let drawable_def = ir
        .type_defs
        .iter()
        .find(|td| &*td.name == "Drawable")
        .unwrap();
    assert_eq!(drawable_def.kind, TypeDefKind::Trait);

    // Impl block
    assert_eq!(ir.impl_blocks.len(), 1);
    assert_eq!(&*ir.impl_blocks[0].self_type, "Foo");
    assert_eq!(ir.impl_blocks[0].trait_name.as_deref(), Some("Drawable"));
}

// 1.T9: Module facts
#[test]
fn test_ir_extracts_modules() {
    let source = r#"
        #[cfg(test)]
        mod tests {
            #[test]
            fn it_works() {}
        }
        mod utils {}
    "#;
    let ir = parse_and_extract(source);

    assert_eq!(ir.modules.len(), 2);

    let test_mod = ir.modules.iter().find(|m| &*m.name == "tests").unwrap();
    assert!(test_mod.is_cfg_test);

    let utils_mod = ir.modules.iter().find(|m| &*m.name == "utils").unwrap();
    assert!(!utils_mod.is_cfg_test);
}

#[test]
fn test_ir_extracts_generic_alias_target_and_argument_edges() {
    let source = include_str!("../fixtures/mixed_concerns_generic_aliases.rs");
    let ir = parse_and_extract(source);
    let edges: Vec<String> = ir
        .type_aliases
        .iter()
        .flat_map(|alias| {
            alias
                .edges
                .iter()
                .map(|(source, target)| format!("{source}->{target}"))
        })
        .collect();

    assert_eq!(
        edges,
        [
            "UnitHandle->Handle",
            "UnitHandle->UnitKind",
            "DefinitionHandle->Handle",
            "DefinitionHandle->DefinitionKind",
            "ReferenceHandle->Handle",
            "ReferenceHandle->ReferenceKind",
        ],
        "each alias connects its declared name to the generic target and marker argument",
    );
}
