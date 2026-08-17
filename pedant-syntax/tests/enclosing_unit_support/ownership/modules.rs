//! Which file a `mod` declaration selects.
//!
//! The one rule the closure walk needs and does not own: reading the names a
//! source declares, and turning each name into the path it resolves to.

use std::path::{Path, PathBuf};

use syn::visit::Visit;

/// The names of every file-backed `mod` declaration in one source, at any
/// depth.
///
/// A walk rather than a read of `file.items`, because a file-backed `mod`
/// nested inside an inline `mod outer { … }` still names a file, and reading
/// only the top level would drop it and everything it holds out of every scan
/// above.
pub(super) fn declared_modules(file: &syn::File) -> Box<[Box<str>]> {
    let mut names = ModuleNames::default();
    names.visit_file(file);
    names.0.into_boxed_slice()
}

/// Collects the name of every `mod name;` a source declares, at any depth.
#[derive(Default)]
struct ModuleNames(Vec<Box<str>>);

impl<'ast> Visit<'ast> for ModuleNames {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        // An inline body is already part of this file, so it names no further
        // member — but it can still declare one, so the walk descends either
        // way.
        if node.content.is_none() {
            self.0.push(node.ident.to_string().into_boxed_str());
        }
        syn::visit::visit_item_mod(self, node);
    }
}

/// The file a `mod name;` declaration inside `owner` selects.
pub(super) fn resolve_module(owner: &Path, name: &str) -> Option<PathBuf> {
    let directory = match owner.file_name().and_then(|name| name.to_str()) {
        Some("lib.rs" | "mod.rs") => owner.parent()?.to_path_buf(),
        _ => owner.with_extension(""),
    };
    let flat = directory.join(format!("{name}.rs"));
    let nested = directory.join(name).join("mod.rs");
    match (flat.is_file(), nested.is_file()) {
        (true, _) => Some(flat),
        (_, true) => Some(nested),
        _ => None,
    }
}
