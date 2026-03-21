use std::rc::Rc;
use std::sync::Arc;

/// Line and column in source (1-based line, 0-based column from syn, +1 at report time).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrSpan {
    pub line: usize,
    pub column: usize,
}

/// All facts extracted from a single file's AST.
#[derive(Debug)]
pub struct FileIr {
    pub file_path: Arc<str>,
    pub functions: Box<[FnFact]>,
    pub type_defs: Box<[TypeDefFact]>,
    pub impl_blocks: Box<[ImplFact]>,
    pub use_paths: Box<[UsePathFact]>,
    pub control_flow: Box<[ControlFlowFact]>,
    pub bindings: Box<[BindingFact]>,
    pub type_refs: Box<[TypeRefFact]>,
    pub method_calls: Box<[MethodCallFact]>,
    pub macro_invocations: Box<[MacroFact]>,
    pub attributes: Box<[AttributeFact]>,
    pub string_literals: Box<[StringLitFact]>,
    pub unsafe_sites: Box<[UnsafeFact]>,
    pub extern_blocks: Box<[ExternBlockFact]>,
    pub modules: Box<[ModuleFact]>,
}

/// A function or method definition.
#[derive(Debug)]
pub struct FnFact {
    pub name: Box<str>,
    pub span: IrSpan,
    pub is_unsafe: bool,
    pub params: Box<[ParamFact]>,
    pub return_type: Option<TypeInfo>,
    pub signature_type_names: Box<[Rc<str>]>,
    pub item_depth: usize,
    pub has_arithmetic: bool,
    /// Pairwise edges from body-referenced types (for mixed-concerns analysis).
    pub body_type_edges: Box<[(Rc<str>, Rc<str>)]>,
}

/// A function parameter.
#[derive(Debug)]
pub struct ParamFact {
    pub name: Box<str>,
    pub type_text: Box<str>,
}

/// Minimal type information extracted from the AST.
#[derive(Debug)]
pub struct TypeInfo {
    pub text: Box<str>,
    pub involves_dyn: bool,
}

/// Else-branch details, only present for If control flow.
#[derive(Debug, Clone, Copy)]
pub struct ElseInfo {
    pub chain_len: Option<usize>,
    pub span: Option<IrSpan>,
}

/// Control flow construct encountered during traversal.
#[derive(Debug)]
pub struct ControlFlowFact {
    pub kind: ControlFlowKind,
    pub span: IrSpan,
    pub depth: usize,
    pub loop_depth: usize,
    pub parent_branch: Option<BranchContext>,
    pub else_info: Option<ElseInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlFlowKind {
    If,
    Match,
    ForLoop,
    WhileLoop,
    Loop,
    Closure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchContext {
    If,
    Match,
}

/// A let binding.
#[derive(Debug)]
pub struct BindingFact {
    pub name: Box<str>,
    pub span: Option<IrSpan>,
    pub loop_depth: usize,
    pub is_refcounted: bool,
    pub is_wildcard: bool,
    pub has_init: bool,
    pub init_is_write_macro: bool,
    pub containing_fn: Option<usize>,
}

/// A type reference encountered in the AST.
#[derive(Debug)]
pub struct TypeRefFact {
    pub text: Box<str>,
    pub span: IrSpan,
    pub involves_dyn: bool,
    pub is_vec_box_dyn: bool,
    pub is_default_hasher: bool,
    pub containing_fn: Option<usize>,
    pub context: TypeRefContext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeRefContext {
    Return,
    Param,
    Field,
    Body,
}

/// A type definition (struct, enum, trait).
#[derive(Debug)]
pub struct TypeDefFact {
    pub name: Rc<str>,
    pub span: IrSpan,
    pub kind: TypeDefKind,
    pub edges: Box<[(Rc<str>, Rc<str>)]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeDefKind {
    Struct,
    Enum,
    Trait,
}

/// An impl block.
#[derive(Debug)]
pub struct ImplFact {
    pub self_type: Rc<str>,
    pub trait_name: Option<Box<str>>,
    pub span: IrSpan,
    pub edges: Box<[(Rc<str>, Rc<str>)]>,
}

/// A use path (flattened from use trees).
#[derive(Debug)]
pub struct UsePathFact {
    pub path: Box<str>,
    pub span: IrSpan,
}

/// A method call expression.
#[derive(Debug)]
pub struct MethodCallFact {
    pub method_name: Box<str>,
    pub text: Box<str>,
    pub span: IrSpan,
    pub receiver_ident: Option<Box<str>>,
    pub loop_depth: usize,
    pub containing_fn: Option<usize>,
}

/// A macro invocation.
#[derive(Debug)]
pub struct MacroFact {
    pub text: Box<str>,
    pub span: IrSpan,
}

/// An attribute on an item.
#[derive(Debug)]
pub struct AttributeFact {
    pub text: Box<str>,
    pub span: IrSpan,
    pub name: Box<str>,
}

/// A string literal.
#[derive(Debug)]
pub struct StringLitFact {
    pub value: Box<str>,
    pub span: IrSpan,
}

/// An unsafe site (block, fn, or impl).
#[derive(Debug)]
pub struct UnsafeFact {
    pub kind: UnsafeKind,
    pub span: IrSpan,
    pub evidence: Box<str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsafeKind {
    Block,
    Fn,
    Impl,
}

/// A bare span fact (used for extern blocks).
#[derive(Debug)]
pub struct ExternBlockFact {
    pub span: IrSpan,
}

/// A module declaration.
#[derive(Debug)]
pub struct ModuleFact {
    pub name: Box<str>,
    pub span: IrSpan,
    pub is_cfg_test: bool,
}
