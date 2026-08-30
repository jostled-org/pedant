//! The completed product tree, read once per case and handed to every claim
//! that case makes.
//!
//! One reading per case rather than one per claim. A case asks four or five
//! questions of the same hundred-odd modules, and parsing per question would
//! both read the tree five times and — worse — let one question range over a set
//! another never saw.
//!
//! The reading is not shared between cases. `syn::File` holds proc-macro spans
//! and is not `Sync`, so a process-wide cache would have to be a lock around a
//! value every case reads and none mutates. Three parses of a hundred files cost
//! less than that lock does to reason about.

use proc_macro2::{Delimiter, Group, TokenStream, TokenTree};
use quote::ToTokens;

use crate::resolution::authority_scan::read_text;
use crate::resolution::code_intelligence::product_model::{
    PRODUCT_MODULE_COUNT, PRODUCT_TREE, PRODUCT_TREES,
};
use crate::resolution::comment_scan::code_index;
use crate::resolution::production_tree::{assert_tree_is_exactly_modelled, tree_modules};
use crate::resolution::tracked_script::tracked_path;

/// One production module of the completed product.
pub(crate) struct ProductModule {
    /// Where the module sits, repository-relative and slash-separated.
    pub(crate) path: Box<str>,
    /// Its syntax tree, as a claim about a route reads it.
    pub(crate) parsed: syn::File,
    /// Every line of `text` that carries code, comments removed, paired with its
    /// one-based number.
    ///
    /// Indexed once at read time rather than per question. One case asks the
    /// same module about a dozen spellings, and each question would otherwise
    /// walk the whole text again to skip the same prose.
    code: Box<[(usize, Box<str>)]>,
    /// Every path this module imports, one fully qualified spelling per leaf.
    ///
    /// `use ignore::{IncrementalIgnore, WalkBuilder};` names `ignore::WalkBuilder`
    /// as surely as `use ignore::WalkBuilder;` does, but no line of it holds
    /// those bytes in that order. A reading that only searched the line would
    /// answer "no" for the grouped form — and worse in the other direction,
    /// because the capability claim is two-sided: `others_stating` asks whether
    /// any module *outside* the named owner reaches a capability, and a module
    /// that grouped the import would have passed that claim while holding the
    /// route. Flattened here so the grouping a formatter chooses cannot decide
    /// what a module is found to name.
    imports: Box<[Box<str>]>,
}

impl ProductModule {
    /// One module built from text rather than read from the tree.
    ///
    /// A claim about what a reading does *not* find needs a subject that states
    /// the searched-for spelling, and no module of the product may state one.
    pub(crate) fn of_text(path: &str, text: &str) -> Self {
        let parsed = syn::parse_file(text)
            .unwrap_or_else(|error| panic!("{path} should parse as Rust: {error}"));
        Self {
            path: path.into(),
            code: code_index(text),
            imports: imported_paths(&parsed),
            parsed,
        }
    }
}

/// Every item one file declares, at every depth.
///
/// Both readers below make a claim about what a module does *not* hold —
/// [`ProductSurface::others_stating`] asks whether any module outside a named
/// owner reaches a capability route, and [`ProductSurface::others_declaring`]
/// whether any module outside it declares a ceiling. A reading that stopped at
/// the top level answered "no" for everything written inside an inline
/// `mod name { … }`, which this product does write: `request.rs` groups its
/// graph-only questions in one so the feature gate is stated once. A grouped
/// import or a second declaration moved one layer in would have satisfied both
/// claims while holding exactly what they forbid.
fn nested_items(items: &[syn::Item]) -> Box<[&syn::Item]> {
    let mut held: Vec<&syn::Item> = Vec::new();
    collect_items(items, &mut held);
    held.into_boxed_slice()
}

fn collect_items<'file>(items: &'file [syn::Item], held: &mut Vec<&'file syn::Item>) {
    for item in items {
        held.push(item);
        collect_items(inline_items(item), held);
    }
}

/// The items one inline module states, and none for every other item.
///
/// A `mod name;` states its items in another file, which the surface reads as a
/// module of its own.
fn inline_items(item: &syn::Item) -> &[syn::Item] {
    match item {
        syn::Item::Mod(syn::ItemMod {
            content: Some((_, items)),
            ..
        }) => items,
        _ => &[],
    }
}

/// Every path a module's `use` items bring into scope, fully qualified.
///
/// Read from the tree rather than the text: a group nests, renames, and glob
/// arms differ only in the tree, and a reader that flattened them by hand would
/// be a second parser to keep correct.
fn imported_paths(parsed: &syn::File) -> Box<[Box<str>]> {
    let mut held: Vec<Box<str>> = Vec::new();
    for item in nested_items(&parsed.items).iter().copied() {
        if let syn::Item::Use(item) = item {
            push_use_tree(&item.tree, &mut String::new(), &mut held);
        }
    }
    held.into_boxed_slice()
}

/// One `use` tree flattened onto `held`, one entry per leaf.
///
/// A rename records the path it renames, not the new name: the claim is about
/// the route a module reaches, and `use ignore::WalkBuilder as W;` reaches it.
fn push_use_tree(tree: &syn::UseTree, prefix: &mut String, held: &mut Vec<Box<str>>) {
    match tree {
        syn::UseTree::Path(path) => {
            let restore = prefix.len();
            qualify(prefix, &path.ident.to_string());
            push_use_tree(&path.tree, prefix, held);
            prefix.truncate(restore);
        }
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                push_use_tree(tree, prefix, held);
            }
        }
        syn::UseTree::Name(name) => held.push(leaf(prefix, &name.ident.to_string())),
        syn::UseTree::Rename(rename) => held.push(leaf(prefix, &rename.ident.to_string())),
        syn::UseTree::Glob(_) => held.push(leaf(prefix, "*")),
    }
}

/// One more segment on the path being built.
fn qualify(prefix: &mut String, segment: &str) {
    if !prefix.is_empty() {
        prefix.push_str("::");
    }
    prefix.push_str(segment);
}

/// One leaf spelled out, leaving the prefix as it was found.
fn leaf(prefix: &str, segment: &str) -> Box<str> {
    let mut spelled = prefix.to_owned();
    qualify(&mut spelled, segment);
    spelled.into_boxed_str()
}

/// Every module of the completed product, in path order.
pub(crate) struct ProductSurface {
    modules: Box<[ProductModule]>,
}

impl ProductSurface {
    /// Read the completed product, proving it is exactly the modelled set first.
    pub(crate) fn read() -> Self {
        let mut modelled: Vec<String> = Vec::new();
        for tree in PRODUCT_TREES {
            assert_tree_is_exactly_modelled(tree);
            modelled.extend(tree_modules(tree));
        }
        assert_eq!(
            modelled.len(),
            PRODUCT_MODULE_COUNT,
            "the product model states {PRODUCT_MODULE_COUNT} modules and listed {}",
            modelled.len()
        );
        modelled.sort_unstable();
        let stated = modelled.len();
        modelled.dedup();
        assert_eq!(
            modelled.len(),
            stated,
            "every product module is modelled exactly once"
        );
        Self {
            modules: modelled.iter().map(|path| read_module(path)).collect(),
        }
    }

    /// Every module the product states.
    pub(crate) fn modules(&self) -> &[ProductModule] {
        &self.modules
    }

    /// One modelled module by its repository-relative path.
    pub(crate) fn module(&self, relative: &str) -> &ProductModule {
        self.modules
            .iter()
            .find(|module| &*module.path == relative)
            .unwrap_or_else(|| panic!("{relative} must be a modelled module of {PRODUCT_TREE}"))
    }

    /// Every module but the named ones that states one of the given spellings.
    ///
    /// The verb is the caller's, because the sentence a failure reads is: one
    /// caller is asking who else names a capability route, another who else
    /// implements an operation. The walk is the same walk, and a second copy of
    /// it is a second module set one of the two could start ranging over.
    pub(crate) fn others_stating(
        &self,
        owners: &[&str],
        verb: &str,
        evidence: &[&str],
    ) -> Box<[String]> {
        self.modules
            .iter()
            .filter(|module| !owners.contains(&&*module.path))
            .flat_map(|module| {
                evidence
                    .iter()
                    .filter(move |spelling| states(module, spelling))
                    .map(move |spelling| format!("{} {verb} {spelling}", module.path))
            })
            .collect()
    }

    /// Every module but the named ones that declares one named type.
    ///
    /// The sibling of [`ProductSurface::others_stating`] over declarations
    /// rather than spellings: a ceiling named in a call is not a ceiling
    /// declared, and only the second is a second owner.
    pub(crate) fn others_declaring(&self, owners: &[&str], name: &str) -> Box<[String]> {
        self.modules
            .iter()
            .filter(|module| !owners.contains(&&*module.path))
            .filter(|module| declarations_of(module, name) > 0)
            .map(|module| format!("{} also declares {name}", module.path))
            .collect()
    }
}

/// One modelled module, read and parsed.
///
/// An unreadable or unparsable module fails here rather than dropping out of
/// every claim below it while each one stays green.
fn read_module(relative: &str) -> ProductModule {
    assert!(
        tracked_path(relative).is_file(),
        "{relative} is modelled but is not a file"
    );
    ProductModule::of_text(relative, &read_text(relative))
}

/// Whether one module states one spelling outside its comments.
pub(crate) fn states(module: &ProductModule, evidence: &str) -> bool {
    module.code.iter().any(|(_, line)| line.contains(evidence))
        || module.imports.iter().any(|path| &**path == evidence)
}

/// How many times one module states one spelling outside its comments.
pub(crate) fn occurrences(module: &ProductModule, needle: &str) -> usize {
    module
        .code
        .iter()
        .map(|(_, line)| line.matches(needle).count())
        .sum()
}

/// One module's whole token stream, documentation dropped and every space
/// removed.
///
/// A call written across three lines and the same call written on one are the
/// same call, and a `contains` over the source text can only find the second.
/// Rendering the tree and dropping the spaces makes a call findable by the
/// spelling a reader would write.
///
/// The documentation has to go first. Only `//` line comments are lost to
/// tokenization: `syn` turns `///` and `//!` into `#[doc = "..."]` attributes
/// that the renderer emits again, and compacting then removes the spaces that
/// held the sentence apart. Every module here documents itself and its public
/// bodies, so without the strip an owner could stop making the call it is
/// claimed to make and go on answering with the sentence written above it.
pub(crate) fn compact_tokens(module: &ProductModule) -> Box<str> {
    let rendered = without_documentation(module.parsed.to_token_stream());
    compact(&rendered.to_string())
}

/// One token stream with every doc attribute removed, at every depth.
fn without_documentation(tokens: TokenStream) -> TokenStream {
    let held: Box<[TokenTree]> = tokens.into_iter().collect();
    let mut kept: Vec<TokenTree> = Vec::new();
    let mut at = 0;
    while at < held.len() {
        match documentation_width(&held[at..]) {
            Some(width) => at += width,
            None => {
                kept.push(without_nested_documentation(&held[at]));
                at += 1;
            }
        }
    }
    kept.into_iter().collect()
}

/// How many tokens the doc attribute starting here occupies, when one does.
///
/// Both spellings are read: the outer `#[doc = "..."]` a `///` becomes and the
/// inner `#![doc = "..."]` a `//!` becomes.
fn documentation_width(tokens: &[TokenTree]) -> Option<usize> {
    let (width, body) = match tokens {
        [TokenTree::Punct(hash), TokenTree::Punct(bang), body, ..]
            if hash.as_char() == '#' && bang.as_char() == '!' =>
        {
            (3, body)
        }
        [TokenTree::Punct(hash), body, ..] if hash.as_char() == '#' => (2, body),
        _ => return None,
    };
    names_documentation(body).then_some(width)
}

/// Whether one bracketed attribute body is a `doc` attribute.
fn names_documentation(body: &TokenTree) -> bool {
    match body {
        TokenTree::Group(group) if group.delimiter() == Delimiter::Bracket => matches!(
            group.stream().into_iter().next(),
            Some(TokenTree::Ident(name)) if name == "doc"
        ),
        _ => false,
    }
}

/// One token with the documentation inside it removed.
fn without_nested_documentation(token: &TokenTree) -> TokenTree {
    match token {
        TokenTree::Group(group) => TokenTree::Group(Group::new(
            group.delimiter(),
            without_documentation(group.stream()),
        )),
        held => held.clone(),
    }
}

/// One rendered fragment with every space removed.
///
/// `Box<str>` rather than `String`: a compacted stream is settled the moment it
/// is built, and every caller either searches it or holds it in a slice that
/// outlives the call.
pub(crate) fn compact(rendered: &str) -> Box<str> {
    rendered.chars().filter(|it| !it.is_whitespace()).collect()
}

/// How many times one module declares one named type.
///
/// Beside the surface rather than beside one of its readers: the module set a
/// declaration is counted over and the module set it is counted *against* are
/// the same set, and [`ProductSurface::others_declaring`] is the second reader.
pub(crate) fn declarations_of(module: &ProductModule, name: &str) -> usize {
    nested_items(&module.parsed.items)
        .iter()
        .copied()
        .filter(|item| declared_name(item).is_some_and(|declared| declared == name))
        .count()
}

/// The name one item declares, when it declares a type.
///
/// The identifier itself, not a rendering of it: a comparison against the
/// modelled name reads the same either way, and the string was allocated once
/// per item of every module the surface holds.
fn declared_name(item: &syn::Item) -> Option<&syn::Ident> {
    match item {
        syn::Item::Struct(declared) => Some(&declared.ident),
        syn::Item::Enum(declared) => Some(&declared.ident),
        syn::Item::Type(declared) => Some(&declared.ident),
        _ => None,
    }
}
