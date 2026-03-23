use std::rc::Rc;
use std::sync::Arc;

/// Line and column in source (1-based line, 0-based column from syn, +1 at report time).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrSpan {
    /// 1-based line number.
    pub line: usize,
    /// 0-based column offset (adjusted to 1-based at report time).
    pub column: usize,
}

/// All facts extracted from a single file's AST.
#[derive(Debug)]
pub struct FileIr {
    /// Absolute path of the source file.
    pub file_path: Arc<str>,
    /// Function and method definitions.
    pub functions: Box<[FnFact]>,
    /// Struct, enum, and trait definitions.
    pub type_defs: Box<[TypeDefFact]>,
    /// Impl blocks (inherent and trait).
    pub impl_blocks: Box<[ImplFact]>,
    /// Flattened use paths.
    pub use_paths: Box<[UsePathFact]>,
    /// Control flow constructs (if, match, loops, closures).
    pub control_flow: Box<[ControlFlowFact]>,
    /// Let bindings.
    pub bindings: Box<[BindingFact]>,
    /// Type references in signatures and bodies.
    pub type_refs: Box<[TypeRefFact]>,
    /// Method call expressions.
    pub method_calls: Box<[MethodCallFact]>,
    /// Macro invocations.
    pub macro_invocations: Box<[MacroFact]>,
    /// Attributes on items.
    pub attributes: Box<[AttributeFact]>,
    /// String literal values.
    pub string_literals: Box<[StringLitFact]>,
    /// Unsafe blocks, functions, and impls.
    pub unsafe_sites: Box<[UnsafeFact]>,
    /// Extern block declarations.
    pub extern_blocks: Box<[ExternBlockFact]>,
    /// Module declarations.
    pub modules: Box<[ModuleFact]>,
}

/// A function or method definition.
#[derive(Debug)]
pub struct FnFact {
    /// Function name.
    pub name: Box<str>,
    /// Source location.
    pub span: IrSpan,
    /// Whether the function is marked `unsafe`.
    pub is_unsafe: bool,
    /// Parameter list.
    pub params: Box<[ParamFact]>,
    /// Return type, if explicitly specified.
    pub return_type: Option<TypeInfo>,
    /// Type names referenced in the signature.
    pub signature_type_names: Box<[Rc<str>]>,
    /// Nesting depth of the item in the module tree.
    pub item_depth: usize,
    /// Whether the body contains arithmetic operators.
    pub has_arithmetic: bool,
    /// Pairwise edges from body-referenced types (for mixed-concerns analysis).
    pub body_type_edges: Box<[(Rc<str>, Rc<str>)]>,
}

/// A function parameter.
#[derive(Debug)]
pub struct ParamFact {
    /// Parameter name (or `self`).
    pub name: Box<str>,
    /// Textual representation of the parameter type.
    pub type_text: Box<str>,
}

/// Minimal type information extracted from the AST.
#[derive(Debug)]
pub struct TypeInfo {
    /// Textual representation of the type.
    pub text: Box<str>,
    /// Whether the type involves dynamic dispatch (`dyn Trait`).
    pub involves_dyn: bool,
}

/// Else-branch details, only present for If control flow.
#[derive(Debug, Clone, Copy)]
pub struct ElseInfo {
    /// Length of the if/else-if chain, if chained.
    pub chain_len: Option<usize>,
    /// Span of the else keyword.
    pub span: Option<IrSpan>,
}

/// Control flow construct encountered during traversal.
#[derive(Debug)]
pub struct ControlFlowFact {
    /// Kind of control flow (if, match, loop, etc.).
    pub kind: ControlFlowKind,
    /// Source location.
    pub span: IrSpan,
    /// Nesting depth within the function body.
    pub depth: usize,
    /// Number of enclosing loops.
    pub loop_depth: usize,
    /// Parent branch context, if nested inside if/match.
    pub parent_branch: Option<BranchContext>,
    /// Else-branch details for `If` nodes.
    pub else_info: Option<ElseInfo>,
}

/// Kind of control flow construct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlFlowKind {
    /// An `if` expression.
    If,
    /// A `match` expression.
    Match,
    /// A `for` loop.
    ForLoop,
    /// A `while` loop.
    WhileLoop,
    /// A bare `loop`.
    Loop,
    /// A closure expression.
    Closure,
}

/// Parent branch context for nested control flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchContext {
    /// Inside an `if` arm.
    If,
    /// Inside a `match` arm.
    Match,
}

/// A let binding.
#[derive(Debug)]
pub struct BindingFact {
    /// Binding name.
    pub name: Box<str>,
    /// Source location (None for desugared bindings).
    pub span: Option<IrSpan>,
    /// Number of enclosing loops.
    pub loop_depth: usize,
    /// Whether the binding holds an Rc or Arc type.
    pub is_refcounted: bool,
    /// Whether the pattern is `_`.
    pub is_wildcard: bool,
    /// Whether the binding has an initializer expression.
    pub has_init: bool,
    /// Whether the initializer is a `write!` macro targeting a String.
    pub init_is_write_macro: bool,
    /// Index into `FileIr::functions` of the enclosing function, if any.
    pub containing_fn: Option<usize>,
    /// Source location of the type annotation, if present.
    pub type_annotation_span: Option<IrSpan>,
    /// Canonical type name after alias resolution (semantic analysis only).
    pub resolved_type: Option<Box<str>>,
}

/// A type reference encountered in the AST.
#[derive(Debug)]
pub struct TypeRefFact {
    /// Textual representation of the type.
    pub text: Box<str>,
    /// Source location.
    pub span: IrSpan,
    /// Whether the type involves dynamic dispatch (`dyn Trait`).
    pub involves_dyn: bool,
    /// Whether the type is `Vec<Box<dyn ...>>`.
    pub is_vec_box_dyn: bool,
    /// Whether the type uses the default hasher.
    pub is_default_hasher: bool,
    /// Index into `FileIr::functions` of the enclosing function, if any.
    pub containing_fn: Option<usize>,
    /// Where this type reference appears (return, param, field, body).
    pub context: TypeRefContext,
}

/// Position where a type reference appears.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeRefContext {
    /// Function return type.
    Return,
    /// Function parameter.
    Param,
    /// Struct or enum field.
    Field,
    /// Function body.
    Body,
}

/// A type definition (struct, enum, trait).
#[derive(Debug)]
pub struct TypeDefFact {
    /// Type name.
    pub name: Rc<str>,
    /// Source location.
    pub span: IrSpan,
    /// Kind of type definition.
    pub kind: TypeDefKind,
    /// Pairwise type-relationship edges for graph analysis.
    pub edges: Box<[(Rc<str>, Rc<str>)]>,
}

/// Kind of type definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeDefKind {
    /// A `struct`.
    Struct,
    /// An `enum`.
    Enum,
    /// A `trait`.
    Trait,
}

/// An impl block.
#[derive(Debug)]
pub struct ImplFact {
    /// The self type being implemented.
    pub self_type: Rc<str>,
    /// Trait name, if this is a trait impl.
    pub trait_name: Option<Box<str>>,
    /// Source location.
    pub span: IrSpan,
    /// Pairwise type-relationship edges for graph analysis.
    pub edges: Box<[(Rc<str>, Rc<str>)]>,
}

/// A use path (flattened from use trees).
#[derive(Debug)]
pub struct UsePathFact {
    /// Full path text (e.g., `std::collections::HashMap`).
    pub path: Box<str>,
    /// Source location.
    pub span: IrSpan,
}

/// A method call expression.
#[derive(Debug)]
pub struct MethodCallFact {
    /// Name of the method being called.
    pub method_name: Box<str>,
    /// Full expression text.
    pub text: Box<str>,
    /// Source location.
    pub span: IrSpan,
    /// Identifier of the receiver, if a simple ident.
    pub receiver_ident: Option<Box<str>>,
    /// Source location of the receiver expression.
    pub receiver_span: IrSpan,
    /// Number of enclosing loops.
    pub loop_depth: usize,
    /// Index into `FileIr::functions` of the enclosing function, if any.
    pub containing_fn: Option<usize>,
    /// Resolved type of the method receiver (semantic analysis only).
    pub receiver_type: Option<Box<str>>,
    /// Whether the receiver implements `Copy` (semantic analysis only).
    pub is_copy_receiver: bool,
}

/// A macro invocation.
#[derive(Debug)]
pub struct MacroFact {
    /// Full macro invocation text.
    pub text: Box<str>,
    /// Source location.
    pub span: IrSpan,
}

/// An attribute on an item.
#[derive(Debug)]
pub struct AttributeFact {
    /// Full attribute text.
    pub text: Box<str>,
    /// Source location.
    pub span: IrSpan,
    /// Attribute name (e.g., `derive`, `cfg`).
    pub name: Box<str>,
}

/// A string literal.
#[derive(Debug)]
pub struct StringLitFact {
    /// Literal value (unescaped content).
    pub value: Box<str>,
    /// Source location.
    pub span: IrSpan,
}

/// An unsafe site (block, fn, or impl).
#[derive(Debug)]
pub struct UnsafeFact {
    /// Kind of unsafe construct.
    pub kind: UnsafeKind,
    /// Source location.
    pub span: IrSpan,
    /// Textual evidence of the unsafe usage.
    pub evidence: Box<str>,
}

/// Kind of unsafe construct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsafeKind {
    /// An `unsafe { }` block.
    Block,
    /// An `unsafe fn`.
    Fn,
    /// An `unsafe impl`.
    Impl,
}

/// A bare span fact (used for extern blocks).
#[derive(Debug)]
pub struct ExternBlockFact {
    /// Source location.
    pub span: IrSpan,
}

/// A module declaration.
#[derive(Debug)]
pub struct ModuleFact {
    /// Module name.
    pub name: Box<str>,
    /// Source location.
    pub span: IrSpan,
    /// Whether the module has `#[cfg(test)]`.
    pub is_cfg_test: bool,
}
