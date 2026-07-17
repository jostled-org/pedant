use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::error::{SupplyChainError, path_text};

/// Walk `mod` declarations from the entry points to every reachable source file.
///
/// Returns crate-relative `./`-prefixed paths in sorted order, so the same crate
/// always hashes identically regardless of filesystem enumeration order.
pub(super) fn collect_reachable_sources(
    crate_root: &Path,
    entry_files: &[PathBuf],
    build_script: Option<&Path>,
) -> Result<Box<[Arc<str>]>, SupplyChainError> {
    let mut visited: BTreeSet<Arc<str>> = BTreeSet::new();
    let mut stack: Vec<PathBuf> = entry_files
        .iter()
        .filter(|f| f.is_file())
        .cloned()
        .collect();

    if let Some(bs) = build_script.filter(|p| p.is_file()) {
        stack.push(bs.to_path_buf());
    }

    while let Some(file) = stack.pop() {
        let relative = relative_path_str(crate_root, &file);
        if !visited.insert(relative) {
            continue;
        }
        let source = fs::read_to_string(&file).map_err(|source| SupplyChainError::ReadFile {
            path: path_text(&file),
            source,
        })?;
        push_child_modules(&module_directory(&file), &source, &mut stack);
    }

    Ok(visited.into_iter().collect::<Vec<_>>().into_boxed_slice())
}

fn push_child_modules(mod_dir: &Path, source: &str, stack: &mut Vec<PathBuf>) {
    stack.extend(
        extract_mod_declarations(source)
            .iter()
            .filter_map(|mod_name| resolve_module_file(mod_dir, mod_name)),
    );
}

/// Resolve `mod name;` to `name.rs`, falling back to `name/mod.rs`.
fn resolve_module_file(mod_dir: &Path, mod_name: &str) -> Option<PathBuf> {
    let candidate_file = mod_dir.join(format!("{mod_name}.rs"));
    if candidate_file.is_file() {
        return Some(candidate_file);
    }
    let candidate_mod = mod_dir.join(mod_name).join("mod.rs");
    candidate_mod.is_file().then_some(candidate_mod)
}

fn relative_path_str(crate_root: &Path, path: &Path) -> Arc<str> {
    let relative = path
        .strip_prefix(crate_root)
        .unwrap_or(path)
        .to_string_lossy();
    Arc::from(format!("./{relative}"))
}

/// The directory a file's child modules live in.
fn module_directory(file_path: &Path) -> PathBuf {
    let stem = file_path.file_stem().and_then(OsStr::to_str).unwrap_or("");
    let parent = file_path.parent().unwrap_or(file_path);
    match stem {
        "lib" | "main" | "mod" => parent.to_path_buf(),
        _ => parent.join(stem),
    }
}

fn extract_mod_declarations(source: &str) -> Box<[Box<str>]> {
    source
        .lines()
        .filter_map(|line| {
            let code = line.split("//").next().unwrap_or("").trim();
            find_mod_declaration(code)
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

fn find_mod_declaration(code: &str) -> Option<Box<str>> {
    if !code.ends_with(';') {
        return None;
    }
    let after_mod = match code.starts_with("mod ") {
        true => &code[4..],
        false => {
            let idx = code.find(" mod ")?;
            &code[idx + 5..]
        }
    };
    let name = after_mod.trim_end_matches(';').trim();
    match is_rust_identifier(name) {
        true => Some(Box::from(name)),
        false => None,
    }
}

fn is_rust_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_alphabetic() => chars.all(|c| c.is_alphanumeric() || c == '_'),
        _ => false,
    }
}
