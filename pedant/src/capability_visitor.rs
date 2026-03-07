use std::sync::Arc;

use pedant_types::{Capability, CapabilityFinding, CapabilityProfile, SourceLocation};
use syn::visit::Visit;
use syn::{UseGlob, UseGroup, UseName, UsePath, UseRename, UseTree};

const NETWORK_PREFIXES: &[(&str, Capability)] = &[
    ("std::net", Capability::Network),
    ("tokio::net", Capability::Network),
    ("reqwest", Capability::Network),
    ("hyper", Capability::Network),
    ("ureq", Capability::Network),
    ("curl", Capability::Network),
    ("tungstenite", Capability::Network),
];

const FILESYSTEM_PREFIXES: &[(&str, Capability)] = &[
    ("std::fs", Capability::FileRead),
    ("tokio::fs", Capability::FileRead),
    ("walkdir", Capability::FileRead),
    ("glob", Capability::FileRead),
    ("tempfile", Capability::FileWrite),
];

const PROCESS_PREFIXES: &[(&str, Capability)] = &[
    ("std::process", Capability::ProcessExec),
    ("tokio::process", Capability::ProcessExec),
    ("duct", Capability::ProcessExec),
];

const ENV_PREFIXES: &[(&str, Capability)] = &[
    ("std::env::var", Capability::EnvAccess),
    ("std::env::vars", Capability::EnvAccess),
    ("dotenvy", Capability::EnvAccess),
    ("envy", Capability::EnvAccess),
];

const ALL_PREFIX_TABLES: &[&[(&str, Capability)]] = &[
    NETWORK_PREFIXES,
    FILESYSTEM_PREFIXES,
    PROCESS_PREFIXES,
    ENV_PREFIXES,
];

/// Specific function-level overrides for filesystem capability splitting.
const FS_WRITE_FUNCTIONS: &[&str] = &[
    "std::fs::write",
    "std::fs::create_dir",
    "std::fs::create_dir_all",
    "std::fs::remove_file",
    "std::fs::remove_dir",
    "std::fs::remove_dir_all",
    "std::fs::rename",
    "std::fs::copy",
    "std::fs::hard_link",
    "std::fs::set_permissions",
    "tokio::fs::write",
    "tokio::fs::create_dir",
    "tokio::fs::create_dir_all",
    "tokio::fs::remove_file",
    "tokio::fs::remove_dir",
    "tokio::fs::remove_dir_all",
    "tokio::fs::rename",
    "tokio::fs::copy",
    "tokio::fs::hard_link",
    "tokio::fs::set_permissions",
];

pub(crate) struct CapabilityVisitor {
    file_path: Arc<str>,
    findings: Vec<CapabilityFinding>,
}

impl CapabilityVisitor {
    pub(crate) fn new(file_path: &str) -> Self {
        Self {
            file_path: Arc::from(file_path),
            findings: Vec::new(),
        }
    }

    pub(crate) fn into_profile(self) -> CapabilityProfile {
        CapabilityProfile {
            findings: self.findings,
        }
    }

    fn match_path(&mut self, path: &str, line: usize, column: usize) {
        let capabilities = resolve_capabilities(path);
        for capability in capabilities {
            self.findings.push(CapabilityFinding {
                capability,
                location: SourceLocation {
                    file: Arc::clone(&self.file_path),
                    line,
                    column,
                },
                evidence: Arc::from(path),
            });
        }
    }
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    path == prefix || path.starts_with(&format!("{prefix}::"))
}

fn resolve_capabilities(path: &str) -> Vec<Capability> {
    if FS_WRITE_FUNCTIONS.contains(&path) {
        return vec![Capability::FileWrite];
    }

    ALL_PREFIX_TABLES
        .iter()
        .flat_map(|table| table.iter())
        .filter(|(prefix, _)| path_matches_prefix(path, prefix))
        .map(|(_, capability)| *capability)
        .collect::<Vec<_>>()
        .into_iter()
        .fold(Vec::new(), |mut acc, cap| {
            if !acc.contains(&cap) {
                acc.push(cap);
            }
            acc
        })
}

fn join_path(prefix: &str, segment: &str) -> String {
    match prefix.is_empty() {
        true => segment.to_string(),
        false => format!("{prefix}::{segment}"),
    }
}

fn flatten_use_tree(tree: &UseTree, prefix: &str) -> Vec<String> {
    match tree {
        UseTree::Path(UsePath { ident, tree, .. }) => {
            flatten_use_tree(tree, &join_path(prefix, &ident.to_string()))
        }
        UseTree::Name(UseName { ident, .. }) => vec![join_path(prefix, &ident.to_string())],
        UseTree::Rename(UseRename { ident, .. }) => vec![join_path(prefix, &ident.to_string())],
        UseTree::Glob(UseGlob { .. }) => vec![join_path(prefix, "*")],
        UseTree::Group(UseGroup { items, .. }) => items
            .iter()
            .flat_map(|item| flatten_use_tree(item, prefix))
            .collect(),
    }
}

/// For glob paths like `std::net::*`, match against the prefix before `::*`.
fn match_glob_path(path: &str) -> Option<&str> {
    path.strip_suffix("::*")
}

impl<'ast> Visit<'ast> for CapabilityVisitor {
    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        let span = node.use_token.span.start();
        let line = span.line;
        let column = span.column + 1;

        let paths = flatten_use_tree(&node.tree, "");
        for path in paths {
            match match_glob_path(&path) {
                Some(prefix) => self.match_path(prefix, line, column),
                None => self.match_path(&path, line, column),
            }
        }

        syn::visit::visit_item_use(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if node.path.segments.len() > 1 {
            let path_str: String = node
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect::<Vec<_>>()
                .join("::");

            let span = node.path.segments.first().map_or_else(
                || {
                    node.path
                        .leading_colon
                        .map_or(proc_macro2::Span::call_site(), |c| c.spans[0])
                },
                |s| s.ident.span(),
            );
            let start = span.start();
            self.match_path(&path_str, start.line, start.column + 1);
        }

        syn::visit::visit_expr_path(self, node);
    }
}
