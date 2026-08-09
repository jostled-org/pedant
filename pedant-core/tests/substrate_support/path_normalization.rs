use std::path::Path;

use pedant_core::resolution::rust::{RelativePathNormalizationError, normalize_relative_path};
use syn::visit::Visit;

use crate::declaration_scan::{crate_path, parse_rust_file};

#[test]
fn relative_text_preserves_the_lexical_root_relative_contract() {
    let root = Path::new("repository");

    assert_eq!(
        normalize_relative_path(root, Path::new("repository/src/./nested.rs")),
        Ok(Box::from("src/nested.rs")),
    );
    assert_eq!(normalize_relative_path(root, root), Ok(Box::from("")));
    assert_eq!(
        normalize_relative_path(root, Path::new("repository/../outside.rs")),
        Ok(Box::from("../outside.rs")),
        "normalization must remain lexical rather than canonicalizing the path",
    );
}

#[test]
fn relative_text_rejects_a_path_outside_the_lexical_root() {
    assert_eq!(
        normalize_relative_path(Path::new("repository"), Path::new("sibling/source.rs")),
        Err(RelativePathNormalizationError::OutsideRoot),
    );
}

#[cfg(unix)]
#[test]
fn relative_text_rejects_a_non_utf8_component() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let root = Path::new("repository");
    let path = root.join(OsString::from_vec(vec![b's', b'r', b'c', 0xff]));

    assert_eq!(
        normalize_relative_path(root, &path),
        Err(RelativePathNormalizationError::NonUtf8),
    );
}

#[test]
fn both_production_callers_invoke_the_shared_authority() {
    let expected = "crate::resolution::path_normalization::relative_text";
    let context = call_paths("src/ir/semantic/context.rs");
    let rust_paths = call_paths("src/resolution/rust/paths.rs");

    assert!(
        context.iter().any(|path| path.as_ref() == expected),
        "semantic context must call {expected}: {context:?}",
    );
    assert!(
        rust_paths.iter().any(|path| path.as_ref() == expected),
        "Rust resolution paths must call {expected}: {rust_paths:?}",
    );
}

#[derive(Default)]
struct CallPaths {
    paths: Vec<Box<str>>,
}

impl<'ast> Visit<'ast> for CallPaths {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.paths.push(
                path.path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::")
                    .into_boxed_str(),
            );
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn call_paths(relative: &str) -> Vec<Box<str>> {
    let syntax = parse_rust_file(&crate_path(relative));
    let mut calls = CallPaths::default();
    calls.visit_file(&syntax);
    calls.paths
}
