use std::fmt;
use std::rc::Rc;
use std::sync::Arc;

use super::sites::{DefinitionSite, ModuleDeclarationSite, ModuleScope, ReferenceSite};

pub use super::dataflow::{DataFlowFact, DataFlowKind};

/// Normalized item visibility, for `item-visibility-policy`.
///
/// [`fmt::Display`] renders the canonical Rust spelling (`private`, `pub`,
/// `pub(crate)`, `pub(super)`, `pub(in <path>)`), which is how policies are
/// written in configuration and compared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Visibility {
    /// No modifier: private to the enclosing module.
    Private,
    /// `pub`.
    Public,
    /// `pub(crate)`.
    Crate,
    /// `pub(super)`.
    Super,
    /// `pub(in <path>)` (or `pub(self)`), carrying the restriction path.
    Restricted(Box<str>),
}

impl fmt::Display for Visibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Private => f.write_str("private"),
            Self::Public => f.write_str("pub"),
            Self::Crate => f.write_str("pub(crate)"),
            Self::Super => f.write_str("pub(super)"),
            Self::Restricted(path) => write!(f, "pub(in {path})"),
        }
    }
}

/// Source position extracted from `syn` spans.
///
/// Line is 1-based. Column is 0-based from syn, adjusted to 1-based at report time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrSpan {
    /// 1-based.
    pub line: usize,
    /// 0-based from syn; adjusted to 1-based at report time.
    pub column: usize,
}

/// All facts extracted from a single source file's AST in one pass.
#[derive(Debug)]
pub struct FileIr {
    /// Absolute path used for violation reporting.
    pub file_path: Arc<str>,
    /// Physical line count of the source file, for `large-source-file`.
    /// `0` when the IR is built directly from a syntax tree without source.
    pub source_line_count: usize,
    /// Function and method definitions with body metadata.
    pub functions: Box<[FnFact]>,
    /// Struct, enum, and trait definitions with type-relationship edges.
    pub type_defs: Box<[TypeDefFact]>,
    /// Free type aliases with target and generic-argument relationships.
    pub type_aliases: Box<[TypeAliasFact]>,
    /// Inherent and trait impl blocks.
    pub impl_blocks: Box<[ImplFact]>,
    /// Flattened `use` paths for capability detection.
    pub use_paths: Box<[UsePathFact]>,
    /// Nesting-tracked control flow constructs.
    pub control_flow: Box<[ControlFlowFact]>,
    /// Let bindings with ownership and type metadata.
    pub bindings: Box<[BindingFact]>,
    /// Type references classified by position (return, param, field, body).
    pub type_refs: Box<[TypeRefFact]>,
    /// Method calls with receiver tracking for clone-in-loop analysis.
    pub method_calls: Box<[MethodCallFact]>,
    /// Macro invocations for forbidden-macro checks.
    pub macro_invocations: Box<[MacroFact]>,
    /// Item attributes for forbidden-attribute checks.
    pub attributes: Box<[AttributeFact]>,
    /// String literals for credential/endpoint detection.
    pub string_literals: Box<[StringLitFact]>,
    /// Unsafe blocks, functions, and impls.
    pub unsafe_sites: Box<[UnsafeFact]>,
    /// Extern block declarations for FFI detection.
    pub extern_blocks: Box<[ExternBlockFact]>,
    /// Module declarations for inline-test detection.
    pub modules: Box<[ModuleFact]>,
    /// Populated only by semantic enrichment; empty otherwise.
    /// `Arc<[T]>` because semantic enrichment shares the cached analysis's
    /// flow slice — no deep copy. Non-semantic paths use an empty Arc.
    pub data_flows: std::sync::Arc<[DataFlowFact]>,
    /// Lexical module scopes; index zero is the source itself.
    pub module_scopes: Box<[ModuleScope]>,
    /// Every `mod` item, which the module closure reads instead of walking the
    /// syntax tree again.
    pub module_declarations: Box<[ModuleDeclarationSite]>,
    /// The authoritative definition sites a resolution report may name.
    pub definition_sites: Box<[DefinitionSite]>,
    /// The authoritative reference sites, one per source occurrence.
    pub reference_sites: Box<[ReferenceSite]>,
}

/// Extracted metadata for a function or method definition.
#[derive(Debug)]
pub struct FnFact {
    /// Identifier of the function.
    pub name: Box<str>,
    /// Location of the `fn` keyword.
    pub span: IrSpan,
    /// Marked `unsafe fn`.
    pub is_unsafe: bool,
    /// Declared parameters.
    pub params: Box<[ParamFact]>,
    /// Explicit return type, if present (excludes implicit `()`).
    pub return_type: Option<TypeInfo>,
    /// Unique type names from parameters and return type, for mixed-concerns edges.
    pub signature_type_names: Box<[Rc<str>]>,
    /// Nesting depth of the item in the module tree.
    pub item_depth: usize,
    /// Whether the body contains arithmetic operators.
    pub has_arithmetic: bool,
    /// Pairwise edges from body-referenced types (for mixed-concerns analysis).
    pub body_type_edges: Box<[(Rc<str>, Rc<str>)]>,
    /// Physical source lines spanned by the body block `{ … }`, inclusive of
    /// both braces. `0` when the function has no body (e.g. a trait method
    /// declaration without a default).
    pub body_line_count: usize,
    /// `true` for methods and associated functions (inside an `impl` or trait);
    /// `false` for free `fn` items.
    pub is_associated: bool,
    /// `Some(self_type)` when this function is defined in an inherent `impl`
    /// block (`impl Type`); `None` for free functions, trait methods, and
    /// trait-impl methods (`impl Trait for Type`).
    pub inherent_method_of: Option<Rc<str>>,
    /// `true` when the body is exactly a single delegating call of the form
    /// `self.<field>.<method>(<args>)`, allowing a trailing `?` and/or `.await`.
    /// Such pure forwarders carry no responsibility of their own.
    pub is_pure_forwarder: bool,
    /// Declared visibility of the item (`private` for trait methods).
    pub visibility: Visibility,
    /// Feature names of the `#[cfg(feature = "…")]` gates enclosing this item
    /// (its own and every ancestor module/impl), for `ungated-test-api`.
    pub cfg_feature_gates: Box<[Rc<str>]>,
    /// Rendered `#[cfg(…)]` predicates — of any kind, not just `feature` —
    /// on this item and every ancestor module/impl within the file. Empty
    /// means the method is in every build of the file.
    pub cfg_predicates: Box<[Rc<str>]>,
}

/// Extracted metadata for a function parameter.
#[derive(Debug)]
pub struct ParamFact {
    /// Identifier or `self`.
    pub name: Box<str>,
    /// Rendered type text for pattern matching.
    pub type_text: Box<str>,
}

/// Rendered type text with dispatch classification.
#[derive(Debug)]
pub struct TypeInfo {
    /// Normalized type text for pattern matching.
    pub text: Box<str>,
    /// Contains `dyn Trait` at any depth.
    pub involves_dyn: bool,
}

/// Else-branch metadata attached to `If` control flow nodes.
#[derive(Debug, Clone, Copy)]
pub struct ElseInfo {
    /// Total branches in the if/else-if chain, when chained.
    pub chain_len: Option<usize>,
    /// Location of the `else` keyword, for `forbid_else` reporting.
    pub span: Option<IrSpan>,
}

/// A control flow construct with nesting context.
#[derive(Debug)]
pub struct ControlFlowFact {
    /// Discriminant: if, match, loop variant, or closure.
    pub kind: ControlFlowKind,
    /// Location of the keyword.
    pub span: IrSpan,
    /// Nesting depth within the function body (for max-depth check).
    pub depth: usize,
    /// Enclosing loop count (for clone-in-loop suppression).
    pub loop_depth: usize,
    /// Set when nested inside an if or match arm.
    pub parent_branch: Option<BranchContext>,
    /// Present only for `If` nodes.
    pub else_info: Option<ElseInfo>,
    /// Index of the function containing this construct.
    pub containing_fn: Option<usize>,
}

/// Discriminant for control flow constructs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlFlowKind {
    /// `if` expression.
    If,
    /// `match` expression.
    Match,
    /// `for .. in` loop.
    ForLoop,
    /// `while` loop.
    WhileLoop,
    /// Bare `loop` (infinite).
    Loop,
    /// Closure expression (counts as nesting).
    Closure,
}

/// Which branch kind encloses a nested control flow node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchContext {
    /// Nested inside an `if` branch.
    If,
    /// Nested inside a `match` arm.
    Match,
}

/// A `let` binding with ownership and context metadata.
#[derive(Debug)]
pub struct BindingFact {
    /// Identifier (or `_` for wildcard).
    pub name: Box<str>,
    /// `None` for compiler-desugared bindings without source spans.
    pub span: Option<IrSpan>,
    /// Enclosing loop count for clone-in-loop analysis.
    pub loop_depth: usize,
    /// `true` when the declared type is `Rc<_>` or `Arc<_>`.
    pub is_refcounted: bool,
    /// `true` when the pattern is `_` (wildcard discard).
    pub is_wildcard: bool,
    /// `true` when an initializer expression is present.
    pub has_init: bool,
    /// `true` when the initializer is `write!`/`writeln!` into a `String` (infallible).
    pub init_is_write_macro: bool,
    /// Index into `FileIr::functions`; links binding to its enclosing function.
    pub containing_fn: Option<usize>,
    /// Present when the binding has an explicit `: Type` annotation.
    pub type_annotation_span: Option<IrSpan>,
    /// Filled by semantic enrichment; canonical type after alias resolution.
    pub resolved_type: Option<Box<str>>,
}

/// A type reference with dispatch and hasher classification.
#[derive(Debug)]
pub struct TypeRefFact {
    /// Normalized type text for pattern matching.
    pub text: Box<str>,
    /// Location of the type in source.
    pub span: IrSpan,
    /// Contains `dyn Trait` at any depth.
    pub involves_dyn: bool,
    /// Matches `Vec<Box<dyn ...>>` pattern.
    pub is_vec_box_dyn: bool,
    /// `HashMap`/`HashSet` without explicit hasher parameter.
    pub is_default_hasher: bool,
    /// Index into `FileIr::functions`; links to enclosing function.
    pub containing_fn: Option<usize>,
    /// Positional context: return, param, field, or body.
    pub context: TypeRefContext,
}

/// Positional context of a type reference, determining which checks apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeRefContext {
    /// In a function return type.
    Return,
    /// In a function parameter.
    Param,
    /// In a struct or enum field.
    Field,
    /// Inside a function body.
    Body,
}

/// Struct, enum, or trait definition with type-relationship edges.
#[derive(Debug)]
pub struct TypeDefFact {
    /// Identifier of the defined type.
    pub name: Rc<str>,
    /// Location of the definition keyword.
    pub span: IrSpan,
    /// Struct, enum, or trait.
    pub kind: TypeDefKind,
    /// Declared visibility of the type.
    pub visibility: Visibility,
    /// Feature names of the `#[cfg(feature = "…")]` gates enclosing this type.
    pub cfg_feature_gates: Box<[Rc<str>]>,
    /// Pairwise type-relationship edges for mixed-concerns graph analysis.
    pub edges: Box<[(Rc<str>, Rc<str>)]>,
}

/// A free type alias and the relationships its target states.
#[derive(Debug)]
pub struct TypeAliasFact {
    /// Identifier of the declared alias.
    pub name: Rc<str>,
    /// Edges from the alias to its target and generic argument types.
    pub edges: Box<[(Rc<str>, Rc<str>)]>,
}

/// Discriminant for type definitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeDefKind {
    /// `struct` definition.
    Struct,
    /// `enum` definition.
    Enum,
    /// `trait` definition.
    Trait,
    /// `union` definition.
    Union,
}

/// An inherent or trait impl block with type-relationship edges.
#[derive(Debug)]
pub struct ImplFact {
    /// The type being implemented on.
    pub self_type: Rc<str>,
    /// `Some` for `impl Trait for Type`, `None` for inherent impls.
    pub trait_name: Option<Box<str>>,
    /// Location of the `impl` keyword.
    pub span: IrSpan,
    /// Rendered `#[cfg(…)]` predicates on this block and every ancestor module
    /// within the file. Empty means the block is in every build of the file.
    pub cfg_predicates: Box<[Rc<str>]>,
    /// Pairwise type-relationship edges for mixed-concerns graph analysis.
    pub edges: Box<[(Rc<str>, Rc<str>)]>,
}

/// A flattened `use` import path for capability detection.
#[derive(Debug)]
pub struct UsePathFact {
    /// Fully qualified path (e.g., `std::collections::HashMap`).
    pub path: Box<str>,
    /// Location of the `use` statement.
    pub span: IrSpan,
}

/// A method call expression with receiver and loop context.
#[derive(Debug)]
pub struct MethodCallFact {
    /// Method identifier (e.g., `clone`, `unwrap`).
    pub method_name: Box<str>,
    /// Full rendered expression for pattern matching.
    pub text: Box<str>,
    /// Location of the method call.
    pub span: IrSpan,
    /// Simple identifier receiver, when not a complex expression.
    pub receiver_ident: Option<Box<str>>,
    /// Location of the receiver for diagnostic pointing.
    pub receiver_span: IrSpan,
    /// Enclosing loop count for clone-in-loop analysis.
    pub loop_depth: usize,
    /// Index into `FileIr::functions`; links to enclosing function.
    pub containing_fn: Option<usize>,
    /// Filled by semantic enrichment; canonical receiver type.
    /// `Arc<str>` so multiple calls on the same binding share one allocation.
    pub receiver_type: Option<Arc<str>>,
    /// Filled by semantic enrichment; suppresses clone-in-loop for `Copy` types.
    pub is_copy_receiver: bool,
}

/// A macro invocation for forbidden-macro checks.
#[derive(Debug)]
pub struct MacroFact {
    /// Rendered macro text (e.g., `println!`) for pattern matching.
    pub text: Box<str>,
    /// Location of the macro call.
    pub span: IrSpan,
}

/// An item attribute for forbidden-attribute and capability checks.
#[derive(Debug)]
pub struct AttributeFact {
    /// Rendered inner text (e.g., `allow(dead_code)`) for pattern matching.
    pub text: Box<str>,
    /// Location of the `#[` token.
    pub span: IrSpan,
    /// Top-level attribute name (e.g., `derive`, `cfg`, `link`).
    pub name: Box<str>,
}

/// A string literal for credential and endpoint detection.
#[derive(Debug)]
pub struct StringLitFact {
    /// Unescaped content of the literal.
    pub value: Box<str>,
    /// Location of the opening quote.
    pub span: IrSpan,
}

/// An unsafe block, function, or impl for safety auditing.
#[derive(Debug)]
pub struct UnsafeFact {
    /// Block, function, or impl.
    pub kind: UnsafeKind,
    /// Location of the `unsafe` keyword.
    pub span: IrSpan,
    /// Snippet of the unsafe code for evidence reporting.
    pub evidence: Box<str>,
}

/// Discriminant for unsafe constructs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsafeKind {
    /// `unsafe { }` block.
    Block,
    /// `unsafe fn` declaration.
    Fn,
    /// `unsafe impl` block.
    Impl,
}

/// An `extern` block declaration for FFI capability detection.
#[derive(Debug)]
pub struct ExternBlockFact {
    /// Location of the `extern` keyword.
    pub span: IrSpan,
}

/// Structural fingerprint for a function, used for duplicate detection.
///
/// Two functions with identical structure (same control flow, same method call
/// count, same binding count) but different names produce the same `skeleton_hash`.
/// `exact_hash` additionally includes method and type reference names.
#[derive(Debug)]
pub struct FnFingerprint {
    /// Index into `FileIr::functions`.
    pub fn_index: usize,
    /// Function name.
    pub name: Box<str>,
    /// Location of the function definition.
    pub span: IrSpan,
    /// Hash of structural shape only (param count, control flow sequence, counts).
    pub skeleton_hash: u64,
    /// Hash of skeleton components plus method names and type reference texts.
    pub exact_hash: u64,
    /// Total number of facts (method calls + bindings + type refs + control flow).
    pub fact_count: usize,
}

/// A `mod` declaration for inline-test detection.
#[derive(Debug)]
pub struct ModuleFact {
    /// Module identifier.
    pub name: Box<str>,
    /// Location of the `mod` keyword.
    pub span: IrSpan,
    /// `true` when annotated with `#[cfg(test)]`.
    pub is_cfg_test: bool,
    /// Rendered `#[cfg(…)]` predicates guarding this declaration. For a file
    /// module (`mod x;`) they guard the whole of `x.rs` / `x/`, which is the
    /// only way that gate is visible from inside those files.
    pub cfg_predicates: Box<[Rc<str>]>,
}
