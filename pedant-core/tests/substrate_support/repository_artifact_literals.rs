//! String-literal extraction for repository-artifact boundary checks.

use syn::visit::{self, Visit};
use syn::{Expr, ExprLit, Lit};

/// Every string literal nested beneath one expression.
pub fn string_literals(expression: &Expr) -> Box<[String]> {
    let mut literals = StringLiterals::default();
    literals.visit_expr(expression);
    literals.values.into_boxed_slice()
}

#[derive(Default)]
struct StringLiterals {
    values: Vec<String>,
}

impl<'ast> Visit<'ast> for StringLiterals {
    fn visit_expr_lit(&mut self, expression: &'ast ExprLit) {
        if let Lit::Str(value) = &expression.lit {
            self.values.push(value.value());
        }
        visit::visit_expr_lit(self, expression);
    }
}
