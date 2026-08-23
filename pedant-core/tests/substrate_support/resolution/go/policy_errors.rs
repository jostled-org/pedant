//! Which typed error enums one Go production source publishes.
//!
//! Read from declarations rather than from behaviour: no run states which
//! variants an enum holds, and a variant deleted as unreachable leaves every
//! behavioural case green.

use quote::ToTokens;
use syn::visit::Visit;

/// One error enum a Go production source publishes.
pub struct ErrorEnum {
    /// The enum's name.
    pub name: Box<str>,
    /// Every variant, in declaration order.
    pub variants: Box<[Box<str>]>,
    /// Whether the declaration derives `thiserror::Error`.
    pub derives_thiserror: bool,
    /// Variants whose payload is untyped: a trait object, or a bare string
    /// standing in for a structured cause.
    pub untyped_variants: Box<[Box<str>]>,
}

/// Every error enum one source publishes.
pub fn error_enums(file: &syn::File) -> Box<[ErrorEnum]> {
    let mut collector = ErrorCollector::default();
    collector.visit_file(file);
    collector.found.into_boxed_slice()
}

#[derive(Default)]
struct ErrorCollector {
    found: Vec<ErrorEnum>,
}

impl<'ast> Visit<'ast> for ErrorCollector {
    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        let name = node.ident.to_string();
        if name.ends_with("Error") {
            self.found.push(ErrorEnum {
                variants: node
                    .variants
                    .iter()
                    .map(|variant| variant.ident.to_string().into_boxed_str())
                    .collect(),
                derives_thiserror: node.attrs.iter().any(derives_thiserror),
                untyped_variants: node
                    .variants
                    .iter()
                    .filter(is_untyped)
                    .map(name_of)
                    .collect(),
                name: name.into_boxed_str(),
            });
        }
        syn::visit::visit_item_enum(self, node);
    }
}

fn name_of(variant: &syn::Variant) -> Box<str> {
    variant.ident.to_string().into_boxed_str()
}

/// Whether one attribute is a derive naming `thiserror::Error`.
fn derives_thiserror(attribute: &syn::Attribute) -> bool {
    attribute.path().is_ident("derive")
        && attribute
            .to_token_stream()
            .to_string()
            .contains("thiserror :: Error")
}

/// Whether a variant carries an untyped payload.
///
/// A trait object hides which stage failed behind a `dyn`, and an unnamed
/// `String` field is the shape a stringly-typed catch-all arrives in. Named
/// `String` fields are ordinary evidence — a module path, a manifest line — and
/// every variant of this surface carries some.
fn is_untyped(variant: &&syn::Variant) -> bool {
    variant.fields.iter().any(|field| {
        let rendered = field.ty.to_token_stream().to_string();
        rendered.contains("dyn ") || (field.ident.is_none() && rendered == "String")
    })
}
