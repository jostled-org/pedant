use std::sync::Arc;

use crate::violation::CheckRationale;

const NESTED_CONDITIONAL_PROBLEM: &str = "Conditional-in-conditional creates combinatorial complexity. A 2-branch if inside a 3-branch match is 6 paths. Hard to ensure all paths are tested.";
const NESTED_CONDITIONAL_FIX: &str = "Use tuple patterns `match (a, b) { ... }`, match guards `Some(x) if x > 0 => ...`, or extract to functions.";
const NESTED_CONDITIONAL_EXCEPTION: &str = "None. Refactoring is always possible.";

/// Catalog entry for a single check, displayed by `--list-checks` and `--explain`.
#[derive(Debug, Clone, Copy)]
pub struct CheckInfo {
    /// Kebab-case identifier (e.g., `"max-depth"`).
    pub code: &'static str,
    /// One-line summary for the checks table.
    pub description: &'static str,
    /// Grouping key (e.g., `"nesting"`, `"dispatch"`, `"structure"`).
    pub category: &'static str,
    /// `true` when the pattern is disproportionately common in LLM output.
    pub llm_specific: bool,
}

/// Defines all check metadata in one place and generates:
/// - `ViolationType` enum (unit and data-carrying variants)
/// - `ViolationType::code()` returning the short code string
/// - `ViolationType::check_name()` returning the category
/// - `ViolationType::rationale()` returning `CheckRationale`
/// - `lookup_rationale()` free function
/// - `ALL_CHECKS` constant array of `CheckInfo`
macro_rules! define_checks {
    // Entry point: collect all check declarations, then emit everything.
    (
        $(
            $variant:ident $({ $field:ident : $ftype:ty })? => {
                code: $code:expr,
                description: $desc:literal,
                category: $cat:expr,
                problem: $problem:expr,
                fix: $fix:expr,
                exception: $exception:expr,
                llm_specific: $llm:expr $(,)?
            }
        ),+ $(,)?
    ) => {
        /// The kind of violation detected.
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum ViolationType {
            $(
                #[doc = $desc]
                $variant $({
                    #[doc = "The matched pattern."]
                    $field: $ftype
                })?,
            )+
        }

        impl ViolationType {
            /// Returns the short code string used in output (e.g., `"max-depth"`).
            pub fn code(&self) -> &'static str {
                match self {
                    $(
                        Self::$variant $({ $field: _ })? => $code,
                    )+
                }
            }

            /// Returns the check category name (e.g., `"nesting"`, `"dispatch"`).
            pub fn check_name(&self) -> &'static str {
                match self {
                    $(
                        Self::$variant $({ $field: _ })? => $cat,
                    )+
                }
            }

            /// Returns the detailed rationale explaining why this check exists.
            pub fn rationale(&self) -> CheckRationale {
                match self {
                    $(
                        Self::$variant $({ $field: _ })? => CheckRationale {
                            problem: $problem,
                            fix: $fix,
                            exception: $exception,
                            llm_specific: $llm,
                        },
                    )+
                }
            }
        }

        /// Look up a ViolationType by its code string for rationale display.
        pub fn lookup_rationale(code: &str) -> Option<CheckRationale> {
            match code {
                $(
                    $code => Some(CheckRationale {
                        problem: $problem,
                        fix: $fix,
                        exception: $exception,
                        llm_specific: $llm,
                    }),
                )+
                _ => None,
            }
        }

        /// All available checks.
        pub const ALL_CHECKS: &[CheckInfo] = &[
            $(
                CheckInfo {
                    code: $code,
                    description: $desc,
                    category: $cat,
                    llm_specific: $llm,
                },
            )+
        ];
    };
}

define_checks! {
    MaxDepth => {
        code: "max-depth",
        description: "Excessive nesting depth",
        category: "nesting",
        problem: "Deeply nested code is hard to read, test, and modify. Each nesting level adds cognitive load. Bugs hide in deep branches.",
        fix: "Extract functions, use early returns, flatten with guard clauses.",
        exception: "Complex parsers or state machines may need deeper nesting locally.",
        llm_specific: false,
    },
    NestedIf => {
        code: "nested-if",
        description: "If nested inside if",
        category: "nesting",
        problem: NESTED_CONDITIONAL_PROBLEM,
        fix: NESTED_CONDITIONAL_FIX,
        exception: NESTED_CONDITIONAL_EXCEPTION,
        llm_specific: false,
    },
    IfInMatch => {
        code: "if-in-match",
        description: "If inside match arm",
        category: "nesting",
        problem: NESTED_CONDITIONAL_PROBLEM,
        fix: NESTED_CONDITIONAL_FIX,
        exception: NESTED_CONDITIONAL_EXCEPTION,
        llm_specific: false,
    },
    NestedMatch => {
        code: "nested-match",
        description: "Match nested inside match",
        category: "nesting",
        problem: NESTED_CONDITIONAL_PROBLEM,
        fix: NESTED_CONDITIONAL_FIX,
        exception: NESTED_CONDITIONAL_EXCEPTION,
        llm_specific: false,
    },
    MatchInIf => {
        code: "match-in-if",
        description: "Match inside if branch",
        category: "nesting",
        problem: NESTED_CONDITIONAL_PROBLEM,
        fix: NESTED_CONDITIONAL_FIX,
        exception: NESTED_CONDITIONAL_EXCEPTION,
        llm_specific: false,
    },
    ElseChain => {
        code: "else-chain",
        description: "Long if/else if chain",
        category: "nesting",
        problem: "Long if/else if/else if chains are unordered match arms in disguise. Easy to miss cases, hard to verify exhaustiveness.",
        fix: "Use `match` on boolean tuples. Precedence becomes explicit, compiler checks exhaustiveness.",
        exception: "None. Any boolean chain can be refactored to a tuple match.",
        llm_specific: false,
    },
    ForbiddenAttribute { pattern: Arc<str> } => {
        code: "forbidden-attribute",
        description: "Forbidden attribute pattern",
        category: "forbid_attributes",
        problem: "Silences warnings that indicate real problems. Dead code is maintenance burden. Unused variables often signal logic errors.",
        fix: "Remove dead code. Use `_` prefix for intentionally unused bindings. Address the underlying issue rather than suppressing.",
        exception: "Generated code, FFI bindings, conditional compilation.",
        llm_specific: true,
    },
    ForbiddenType { pattern: Arc<str> } => {
        code: "forbidden-type",
        description: "Forbidden type pattern",
        category: "forbid_types",
        problem: "Certain type patterns indicate suboptimal design. Arc<String> has double indirection. Box<dyn Error> is superseded by better alternatives.",
        fix: "Use Arc<str> instead of Arc<String>. Use thiserror or anyhow instead of Box<dyn Error>.",
        exception: "When mutation methods are needed via Arc::make_mut(), or legacy API interop.",
        llm_specific: true,
    },
    ForbiddenCall { pattern: Arc<str> } => {
        code: "forbidden-call",
        description: "Forbidden method call pattern",
        category: "forbid_calls",
        problem: ".unwrap() and .expect() panic on failure with no recovery. .clone() hides allocations.",
        fix: "Use `?` for propagation. Use .unwrap_or(), .unwrap_or_default() for defaults. Restructure ownership to avoid clone.",
        exception: "Human-authored code may use .unwrap() on provably infallible paths with documented invariants. Does not apply to LLM-generated code.",
        llm_specific: true,
    },
    ForbiddenMacro { pattern: Arc<str> } => {
        code: "forbidden-macro",
        description: "Forbidden macro pattern",
        category: "forbid_macros",
        problem: "panic!/todo!/unimplemented! crash at runtime. dbg!/println! are debug artifacts that shouldn't be committed.",
        fix: "Return Result instead of panicking. Use proper logging (tracing, log) for diagnostics. Implement functionality instead of stubbing.",
        exception: "Invariant assertions for bugs (not expected failures). CLI tools where stdout is the interface.",
        llm_specific: true,
    },
    ForbiddenElse => {
        code: "forbidden-else",
        description: "Use of `else` keyword (style preference)",
        category: "forbid_else",
        problem: "`else` creates implicit branches. `match` makes all branches explicit and compiler-checked.",
        fix: "Use `match` for multi-way branches. Use early return with guard clauses instead of if/else.",
        exception: "This is a style preference. Clippy recommends if/else for simple boolean conditions (match_bool lint). Disable with `forbid_else = false` if you disagree.",
        llm_specific: false,
    },
    ForbiddenUnsafe => {
        code: "forbidden-unsafe",
        description: "Use of `unsafe` keyword",
        category: "forbid_unsafe",
        problem: "`unsafe` bypasses Rust's safety guarantees. Memory corruption, undefined behavior, and security vulnerabilities become possible.",
        fix: "Use safe abstractions. Wrap unsafe in minimal, well-audited modules with safe public APIs.",
        exception: "FFI bindings, performance-critical code with proven safety invariants, implementing safe abstractions over unsafe primitives.",
        llm_specific: false,
    },
    DynReturn => {
        code: "dyn-return",
        description: "Dynamic dispatch in return type (`Box<dyn T>`, `Arc<dyn T>`)",
        category: "dispatch",
        problem: "Returning Box<dyn Trait> or Arc<dyn Trait> forces vtable dispatch on every call. The vtable lookup prevents inlining and all downstream optimizations.",
        fix: "Use enum dispatch for a closed set of types. Use `impl Trait` when the caller doesn't need to store heterogeneously. Use a generic type parameter when the concrete type varies per call site.",
        exception: "Plugin systems or FFI boundaries where the set of concrete types is truly open-ended and unknown at compile time.",
        llm_specific: true,
    },
    DynParam => {
        code: "dyn-param",
        description: "Dynamic dispatch in function parameter (`&dyn T`, `Box<dyn T>`)",
        category: "dispatch",
        problem: "Accepting &dyn Trait or Box<dyn Trait> as a parameter forces vtable dispatch per call. The compiler cannot monomorphize or inline the callee's methods.",
        fix: "Use a generic parameter `T: Trait` or `impl Trait` to enable monomorphization. The compiler generates specialized code for each concrete type, enabling inlining.",
        exception: "When the function is called with many distinct concrete types and binary size is a concern, or when storing heterogeneous collections.",
        llm_specific: true,
    },
    VecBoxDyn => {
        code: "vec-box-dyn",
        description: "`Vec<Box<dyn T>>` prevents cache locality and inlining",
        category: "dispatch",
        problem: "Vec<Box<dyn Trait>> incurs per-element heap allocation, vtable dispatch on every access, and scattered memory that defeats cache prefetching.",
        fix: "Use an enum wrapping the known concrete types. Elements are stored inline in the Vec with no vtable and no per-element allocation.",
        exception: "Plugin systems where concrete types are loaded at runtime and cannot be enumerated at compile time.",
        llm_specific: true,
    },
    DynField => {
        code: "dyn-field",
        description: "Dynamic dispatch in struct field (`Box<dyn T>`, `Arc<dyn T>`)",
        category: "dispatch",
        problem: "A Box<dyn Trait> or Arc<dyn Trait> struct field permanently commits every method call on that field to vtable dispatch. This prevents inlining for the lifetime of the struct.",
        fix: "Make the struct generic over the trait: `struct Foo<T: Trait> { field: T }`. The compiler monomorphizes each instantiation, enabling static dispatch and inlining.",
        exception: "When the struct must hold different concrete types at different times, or when the concrete type is determined at runtime (e.g., configuration-driven).",
        llm_specific: true,
    },
    CloneInLoop => {
        code: "clone-in-loop",
        description: "clone() called inside loop body (Arc/Rc suppressed when type is visible)",
        category: "performance",
        problem: ".clone() inside a loop body means N heap allocations where N is the iteration count. LLMs add .clone() to satisfy the borrow checker without considering the per-iteration cost. Arc/Rc clones are automatically suppressed when the type is visible (explicit type annotations or containers with Arc/Rc generic args). Type aliases that hide Arc/Rc (e.g., type MyMap = BTreeMap<Arc<str>, Arc<str>>) cannot be resolved and may cause false positives.",
        fix: "Borrow instead of cloning. Use Cow<T> for conditional ownership. Use Rc/Arc for shared ownership. Restructure to move ownership before the loop.",
        exception: "When the cloned value is mutated independently per iteration and borrowing is not possible.",
        llm_specific: true,
    },
    DefaultHasher => {
        code: "default-hasher",
        description: "HashMap/HashSet with default SipHash hasher",
        category: "performance",
        problem: "HashMap/HashSet default to SipHash, designed for HashDoS resistance. SipHash is 2-5x slower than FxHash or AHash for typical keys (integers, short strings).",
        fix: "Use rustc_hash::FxHashMap for integer keys. Use ahash::AHashMap for general-purpose fast hashing. Specify the hasher explicitly: HashMap<K, V, S>.",
        exception: "When keys come from untrusted input (network, user-provided) and HashDoS resistance is required.",
        llm_specific: true,
    },
    MixedConcerns => {
        code: "mixed-concerns",
        description: "Disconnected type groups indicate mixed concerns",
        category: "structure",
        problem: "Disconnected type groups in a single file indicate mixed concerns. Types that share no fields, trait bounds, or function signatures belong in separate modules.",
        fix: "Split the file along connected components. Each group of related types becomes its own module.",
        exception: "Re-export modules or files that intentionally collect small, independent items (e.g., error enums).",
        llm_specific: true,
    },
    InlineTests => {
        code: "inline-tests",
        description: "Test module embedded in source file",
        category: "structure",
        problem: "Test modules embedded in source files mix production code with test code. This inflates source files and makes test organization harder to navigate.",
        fix: "Move tests to the tests/ directory as integration tests, or to a separate test file alongside the source.",
        exception: "Small utility modules where colocated unit tests are preferred for locality.",
        llm_specific: true,
    },
    GenericNaming => {
        code: "generic-naming",
        description: "High ratio of generic variable names in a function",
        category: "naming",
        problem: "LLMs generate generic names like `tmp`, `data`, `val` because training data is saturated with them. System prompt rules like 'use descriptive names' compete with this statistical bias and lose.",
        fix: "Use domain-specific names that describe what the value represents: `user_id` not `val`, `retry_count` not `tmp`, `response_body` not `data`.",
        exception: "Small utility functions (fewer than 2 generic names) where short names are conventional.",
        llm_specific: true,
    },
    LetUnderscoreResult => {
        code: "let-underscore-result",
        description: "let _ = discards a potentially fallible Result",
        category: "structure",
        problem: "Silently discarding a Result hides errors that surface only in production.",
        fix: "Handle the error with `?`, `match`, or `if let Err`; or use `.expect()` with a reason if the error is truly impossible.",
        exception: "`write!`/`writeln!` to a `String` binding — fmt::Write for String is infallible.",
        llm_specific: true,
    },
    HighParamCount => {
        code: "high-param-count",
        description: "Function has too many parameters",
        category: "structure",
        problem: "Functions with many parameters are hard to call correctly. Callers must remember argument order, and adding parameters is a breaking change at every call site.",
        fix: "Group related parameters into a struct. Use the builder pattern for optional configuration. Split the function if parameters serve different concerns.",
        exception: "FFI bindings that must match an external C signature.",
        llm_specific: true,
    },
}
