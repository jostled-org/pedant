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

const FFI_PREFIXES: &[(&str, Capability)] = &[
    ("libc", Capability::Ffi),
    ("nix", Capability::Ffi),
    ("winapi", Capability::Ffi),
    ("windows_sys", Capability::Ffi),
];

const CRYPTO_PREFIXES: &[(&str, Capability)] = &[
    ("ring", Capability::Crypto),
    ("rustls", Capability::Crypto),
    ("openssl", Capability::Crypto),
    ("aes", Capability::Crypto),
    ("sha2", Capability::Crypto),
    ("hmac", Capability::Crypto),
    ("ed25519_dalek", Capability::Crypto),
    ("x25519_dalek", Capability::Crypto),
];

const SYSTEM_TIME_PREFIXES: &[(&str, Capability)] = &[
    ("std::time::SystemTime", Capability::SystemTime),
    ("std::time::Instant", Capability::SystemTime),
    ("chrono", Capability::SystemTime),
    ("time", Capability::SystemTime),
];

const ALL_PREFIX_TABLES: &[&[(&str, Capability)]] = &[
    NETWORK_PREFIXES,
    FILESYSTEM_PREFIXES,
    PROCESS_PREFIXES,
    ENV_PREFIXES,
    FFI_PREFIXES,
    CRYPTO_PREFIXES,
    SYSTEM_TIME_PREFIXES,
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
            self.record_finding(capability, path, line, column);
        }
    }

    fn check_string_literal(&mut self, lit_str: &syn::LitStr) {
        let value = lit_str.value();
        let start = lit_str.span().start();
        let line = start.line;
        let column = start.column + 1;
        let is_endpoint = check_string_for_endpoint(&value);
        let is_pem = check_string_for_pem(&value);

        match (is_endpoint, is_pem) {
            (true, true) => {
                self.record_finding(Capability::Network, &value, line, column);
                self.record_finding(Capability::Crypto, &value, line, column);
            }
            (true, false) => self.record_finding(Capability::Network, &value, line, column),
            (false, true) => self.record_finding(Capability::Crypto, &value, line, column),
            (false, false) => {}
        }
    }

    fn record_finding(
        &mut self,
        capability: Capability,
        evidence: &str,
        line: usize,
        column: usize,
    ) {
        self.findings.push(CapabilityFinding {
            capability,
            location: SourceLocation {
                file: Arc::clone(&self.file_path),
                line,
                column,
            },
            evidence: Arc::from(evidence),
        });
    }
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    path == prefix
        || (path.starts_with(prefix)
            && path.as_bytes().get(prefix.len()..prefix.len() + 2) == Some(b"::"))
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

const MAX_USE_TREE_DEPTH: usize = 32;

fn flatten_use_tree(tree: &UseTree, prefix: &str, depth: usize) -> Vec<String> {
    if depth > MAX_USE_TREE_DEPTH {
        return Vec::new();
    }
    match tree {
        UseTree::Path(UsePath { ident, tree, .. }) => {
            flatten_use_tree(tree, &join_path(prefix, &ident.to_string()), depth + 1)
        }
        UseTree::Name(UseName { ident, .. }) => vec![join_path(prefix, &ident.to_string())],
        UseTree::Rename(UseRename { ident, .. }) => vec![join_path(prefix, &ident.to_string())],
        UseTree::Glob(UseGlob { .. }) => vec![join_path(prefix, "*")],
        UseTree::Group(UseGroup { items, .. }) => items
            .iter()
            .flat_map(|item| flatten_use_tree(item, prefix, depth + 1))
            .collect(),
    }
}

/// For glob paths like `std::net::*`, match against the prefix before `::*`.
fn match_glob_path(path: &str) -> Option<&str> {
    path.strip_suffix("::*")
}

const URL_SCHEMES: &[&str] = &["http://", "https://", "ws://", "wss://"];

fn attribute_path_string(attr: &syn::Attribute) -> String {
    let mut segs = attr.path().segments.iter();
    let Some(first) = segs.next() else {
        return String::new();
    };
    segs.fold(first.ident.to_string(), |mut acc, s| {
        acc.push_str("::");
        acc.push_str(&s.ident.to_string());
        acc
    })
}

fn check_string_for_endpoint(value: &str) -> bool {
    if value.len() < 8 {
        return false;
    }
    URL_SCHEMES.iter().any(|s| value.starts_with(s))
        || looks_like_ipv4(value)
        || looks_like_ipv6(value)
}

fn strip_port_suffix(s: &str) -> Option<&str> {
    let pos = s.rfind(':')?;
    let (host, port) = s.split_at(pos);
    port[1..].parse::<u16>().ok().map(|_| host)
}

fn looks_like_ipv4(s: &str) -> bool {
    let host = match (s.rfind(':'), strip_port_suffix(s)) {
        (Some(_), Some(h)) => h,
        (Some(_), None) => return false,
        (None, _) => s,
    };
    let mut parts = host.split('.');
    let mut count = 0;
    let valid = parts.all(|p| {
        count += 1;
        p.parse::<u8>().is_ok()
    });
    valid && count == 4
}

fn extract_ipv6_body(s: &str) -> &str {
    s.strip_prefix('[')
        .and_then(|inner| {
            inner
                .strip_suffix(']')
                .or_else(|| inner.rfind("]:").map(|pos| &inner[..pos]))
        })
        .unwrap_or(s)
}

fn looks_like_ipv6(s: &str) -> bool {
    let trimmed = extract_ipv6_body(s);
    let mut groups = trimmed.split(':');
    let mut count = 0;
    let valid = groups.all(|g| {
        count += 1;
        g.is_empty() || g.chars().all(|c| c.is_ascii_hexdigit())
    });
    valid && count > 2
}

fn check_string_for_pem(value: &str) -> bool {
    value.contains("-----BEGIN ")
}

impl<'ast> Visit<'ast> for CapabilityVisitor {
    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        let span = node.use_token.span.start();
        let line = span.line;
        let column = span.column + 1;

        let paths = flatten_use_tree(&node.tree, "", 0);
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

    fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
        let start = node.unsafe_token.span.start();
        self.record_finding(
            Capability::UnsafeCode,
            "unsafe block",
            start.line,
            start.column + 1,
        );
        syn::visit::visit_expr_unsafe(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if let Some(token) = node.sig.unsafety {
            let start = token.span.start();
            self.record_finding(
                Capability::UnsafeCode,
                "unsafe fn",
                start.line,
                start.column + 1,
            );
        }
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if let Some(token) = node.sig.unsafety {
            let start = token.span.start();
            self.record_finding(
                Capability::UnsafeCode,
                "unsafe fn",
                start.line,
                start.column + 1,
            );
        }
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if let Some(token) = node.unsafety {
            let start = token.span.start();
            self.record_finding(
                Capability::UnsafeCode,
                "unsafe impl",
                start.line,
                start.column + 1,
            );
        }
        syn::visit::visit_item_impl(self, node);
    }

    fn visit_item_foreign_mod(&mut self, node: &'ast syn::ItemForeignMod) {
        let start = node.abi.extern_token.span.start();
        self.record_finding(
            Capability::Ffi,
            "extern block",
            start.line,
            start.column + 1,
        );
        syn::visit::visit_item_foreign_mod(self, node);
    }

    fn visit_attribute(&mut self, node: &'ast syn::Attribute) {
        let path = attribute_path_string(node);
        let start = node.pound_token.spans[0].start();
        let line = start.line;
        let column = start.column + 1;

        match path.as_str() {
            "link" => self.record_finding(Capability::Ffi, "#[link]", line, column),
            "proc_macro" => {
                self.record_finding(Capability::ProcMacro, "#[proc_macro]", line, column)
            }
            "proc_macro_derive" => {
                self.record_finding(Capability::ProcMacro, "#[proc_macro_derive]", line, column)
            }
            "proc_macro_attribute" => self.record_finding(
                Capability::ProcMacro,
                "#[proc_macro_attribute]",
                line,
                column,
            ),
            _ => {}
        }
    }

    fn visit_expr_lit(&mut self, node: &'ast syn::ExprLit) {
        if let syn::Lit::Str(ref lit_str) = node.lit {
            self.check_string_literal(lit_str);
        }
        syn::visit::visit_expr_lit(self, node);
    }
}
