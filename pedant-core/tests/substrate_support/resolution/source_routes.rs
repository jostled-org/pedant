//! Which forbidden routes one production source takes.
//!
//! A text scan cannot answer this: `unwrap` appears in prose above the function
//! that does not call it, and `dyn` appears inside a doc link. The tree can.

use quote::ToTokens;
use syn::visit::Visit;

/// Macros a production source may not invoke.
///
/// Each aborts the process, prints outside a returned value, or asserts a claim
/// a caller cannot handle. An owner refuses through its typed error instead.
pub(crate) const FORBIDDEN_MACROS: &[&str] = &[
    "assert",
    "assert_eq",
    "assert_ne",
    "dbg",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
    "eprint",
    "eprintln",
    "panic",
    "print",
    "println",
    "todo",
    "unimplemented",
    "unreachable",
];

/// Methods a production source may not call.
///
/// Each turns an absent value into a panic. Every absence in a production
/// surface is a refusal a caller reads from a typed error.
pub(crate) const FORBIDDEN_METHODS: &[&str] = &["expect", "expect_err", "unwrap", "unwrap_err"];

/// Which families of forbidden route one caller is asking about.
///
/// Every family is selected here rather than filtered afterwards. Two callers
/// used to hand the walk an empty macro list and then discard everything except
/// the two literals they wanted, while a third discarded exactly those two — so
/// the walk answered a question neither of them asked, and a family added to it
/// would have arrived in both readings unnoticed.
pub(crate) struct RouteFamilies {
    /// The macros to report; an empty list asks about none.
    pub(crate) macros: &'static [&'static str],
    /// The methods to report; an empty list asks about none.
    pub(crate) methods: &'static [&'static str],
    /// Whether `#[test]` and `mod tests` are reported.
    pub(crate) inline_tests: bool,
    /// Whether a `dyn` bound is reported.
    pub(crate) trait_objects: bool,
}

/// Every route a production owner may not take.
///
/// Its one caller is the Go policy case, which compiles under `go-resolution`
/// alone, so the row carries that gate rather than sitting unread in a default
/// build.
#[cfg(feature = "go-resolution")]
pub(crate) const PRODUCTION_ROUTES: RouteFamilies = RouteFamilies {
    macros: FORBIDDEN_MACROS,
    methods: FORBIDDEN_METHODS,
    inline_tests: true,
    trait_objects: true,
};

/// The same routes, less the inline tests a separate inventory owns.
///
/// The integration-root budget is what rejects a case declared inside a
/// production module, and it reports one under the name the budget uses. A
/// second reading here would report the same declaration twice under two
/// different sentences.
pub(crate) const PRODUCT_ROUTES: RouteFamilies = RouteFamilies {
    macros: FORBIDDEN_MACROS,
    methods: FORBIDDEN_METHODS,
    inline_tests: false,
    trait_objects: true,
};

/// The inline-test declarations alone.
pub(crate) const INLINE_TESTS: RouteFamilies = RouteFamilies {
    macros: &[],
    methods: &[],
    inline_tests: true,
    trait_objects: false,
};

/// Every forbidden route one source takes, reported as the route it took.
pub(crate) fn forbidden_routes(file: &syn::File, families: &RouteFamilies) -> Box<[Box<str>]> {
    let mut scan = RouteScan {
        families,
        found: Vec::new(),
    };
    scan.visit_file(file);
    scan.found.into_boxed_slice()
}

/// Every family a caller selects is one this walk still reports.
///
/// All three callers spell their claim as "no offender", so the healthy tree
/// they run against holds no positive subject and a walk that stopped visiting
/// reports every surface clean while each claim passes having read nothing.
/// This is the sentinel that keeps them honest, and it is generated from the
/// same tables the walk matches on, so a route added to a family arrives here
/// rather than being written down a second time.
///
/// Both directions, because selection is the other half of the contract: a
/// family this caller did not ask for must go unreported on a source that takes
/// it. Without that, `INLINE_TESTS` and `PRODUCT_ROUTES` could both be answered
/// by one walk that reports everything it sees.
#[test]
fn every_selected_route_family_is_reported_and_no_other_is() {
    assert_routes_are_reported(&PRODUCT_ROUTES);
    assert_routes_are_reported(&INLINE_TESTS);
}

/// One generated source taking every route, read through one caller's families.
fn assert_routes_are_reported(families: &RouteFamilies) {
    let source = sentinel_source(families);
    let parsed = syn::parse_file(&source).expect("the generated sentinel parses as Rust");
    let reported = forbidden_routes(&parsed, families);
    let holds = |route: &str| reported.iter().any(|found| &**found == route);
    let holds_any = |prefix: &str| reported.iter().any(|found| found.starts_with(prefix));

    for named in families.macros {
        let route = format!("{named}!");
        assert!(holds(&route), "the walk stopped reporting {route}");
    }
    for named in families.methods {
        let route = format!(".{named}()");
        assert!(holds(&route), "the walk stopped reporting {route}");
    }
    assert_eq!(
        holds("#[test]") && holds("mod tests"),
        families.inline_tests,
        "an inline test is reported exactly when the caller selected it"
    );
    assert_eq!(
        holds_any("dyn "),
        families.trait_objects,
        "a trait object is reported exactly when the caller selected it"
    );
}

/// A source taking every route any family names, whatever this caller selected.
///
/// The unselected routes are written too. A sentinel holding only what its
/// caller asked about could not tell a walk that selects from one that reports
/// whatever it sees.
fn sentinel_source(families: &RouteFamilies) -> String {
    let mut source = String::from("fn takes_every_route(subject: Sentinel) {\n");
    for named in families.macros {
        source.push_str(&format!("    {named}!();\n"));
    }
    for named in families.methods {
        source.push_str(&format!("    subject.{named}();\n"));
    }
    source.push_str("}\n");
    source.push_str("#[test]\nfn declared_inline() {}\n");
    source.push_str("mod tests {}\n");
    source.push_str("fn names_a_trait_object(_: &dyn Sentinel) {}\n");
    source
}

/// Which forbidden routes a source takes.
struct RouteScan<'model> {
    families: &'model RouteFamilies,
    found: Vec<Box<str>>,
}

impl RouteScan<'_> {
    fn report(&mut self, route: String) {
        self.found.push(route.into_boxed_str());
    }
}

impl<'ast> Visit<'ast> for RouteScan<'_> {
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let named = node
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();
        if self.families.macros.contains(&named.as_str()) {
            self.report(format!("{named}!"));
        }
        syn::visit::visit_macro(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let named = node.method.to_string();
        if self.families.methods.contains(&named.as_str()) {
            self.report(format!(".{named}()"));
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_attribute(&mut self, node: &'ast syn::Attribute) {
        if self.families.inline_tests && node.path().is_ident("test") {
            self.report("#[test]".to_owned());
        }
        syn::visit::visit_attribute(self, node);
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if self.families.inline_tests && node.ident == "tests" {
            self.report("mod tests".to_owned());
        }
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_type_trait_object(&mut self, node: &'ast syn::TypeTraitObject) {
        if self.families.trait_objects {
            self.report(format!("dyn {}", node.bounds.to_token_stream()));
        }
        syn::visit::visit_type_trait_object(self, node);
    }
}
