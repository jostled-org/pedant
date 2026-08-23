//! Which forbidden routes one Go production source takes.
//!
//! A text scan cannot answer this: `unwrap` appears in prose above the function
//! that does not call it, and `dyn` appears inside a doc link. The tree can.

use quote::ToTokens;
use syn::visit::Visit;

/// Every forbidden route one source takes, reported as the route it took.
pub fn forbidden_routes(file: &syn::File, macros: &[&str], methods: &[&str]) -> Box<[Box<str>]> {
    let mut scan = RouteScan {
        macros,
        methods,
        found: Vec::new(),
    };
    scan.visit_file(file);
    scan.found.into_boxed_slice()
}

/// Which forbidden routes a source takes.
struct RouteScan<'model> {
    macros: &'model [&'model str],
    methods: &'model [&'model str],
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
        if self.macros.contains(&named.as_str()) {
            self.report(format!("{named}!"));
        }
        syn::visit::visit_macro(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let named = node.method.to_string();
        if self.methods.contains(&named.as_str()) {
            self.report(format!(".{named}()"));
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_attribute(&mut self, node: &'ast syn::Attribute) {
        if node.path().is_ident("test") {
            self.report("#[test]".to_owned());
        }
        syn::visit::visit_attribute(self, node);
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if node.ident == "tests" {
            self.report("mod tests".to_owned());
        }
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_type_trait_object(&mut self, node: &'ast syn::TypeTraitObject) {
        self.report(format!("dyn {}", node.bounds.to_token_stream()));
        syn::visit::visit_type_trait_object(self, node);
    }
}
