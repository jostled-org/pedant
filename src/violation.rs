use std::fmt;

/// Rationale explaining why a check exists and how to address it.
#[derive(Debug, Clone, Copy)]
pub struct CheckRationale {
    /// What problem this check detects.
    pub problem: &'static str,
    /// How to fix code that triggers this check.
    pub fix: &'static str,
    /// When exceptions to this check are acceptable.
    pub exception: &'static str,
    /// Whether this check is particularly relevant for LLM-generated code.
    pub llm_specific: bool,
}

/// Look up a ViolationType by its code string for rationale display.
pub fn lookup_rationale(code: &str) -> Option<CheckRationale> {
    match code {
        "max-depth" => Some(ViolationType::MaxDepth.rationale()),
        "nested-if" => Some(ViolationType::NestedIf.rationale()),
        "if-in-match" => Some(ViolationType::IfInMatch.rationale()),
        "nested-match" => Some(ViolationType::NestedMatch.rationale()),
        "match-in-if" => Some(ViolationType::MatchInIf.rationale()),
        "else-chain" => Some(ViolationType::ElseChain.rationale()),
        "forbidden-attribute" => Some(ViolationType::ForbiddenAttribute { pattern: String::new() }.rationale()),
        "forbidden-type" => Some(ViolationType::ForbiddenType { pattern: String::new() }.rationale()),
        "forbidden-call" => Some(ViolationType::ForbiddenCall { pattern: String::new() }.rationale()),
        "forbidden-macro" => Some(ViolationType::ForbiddenMacro { pattern: String::new() }.rationale()),
        "forbidden-else" => Some(ViolationType::ForbiddenElse.rationale()),
        "forbidden-unsafe" => Some(ViolationType::ForbiddenUnsafe.rationale()),
        "dyn-return" => Some(ViolationType::DynReturn.rationale()),
        "dyn-param" => Some(ViolationType::DynParam.rationale()),
        "vec-box-dyn" => Some(ViolationType::VecBoxDyn.rationale()),
        "dyn-field" => Some(ViolationType::DynField.rationale()),
        "clone-in-loop" => Some(ViolationType::CloneInLoop.rationale()),
        "default-hasher" => Some(ViolationType::DefaultHasher.rationale()),
        "mixed-concerns" => Some(ViolationType::MixedConcerns.rationale()),
        "inline-tests" => Some(ViolationType::InlineTests.rationale()),
        _ => None,
    }
}

/// The kind of violation detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViolationType {
    /// Nesting depth exceeds the configured limit.
    MaxDepth,
    /// `if` nested inside another `if`.
    NestedIf,
    /// `if` inside a `match` arm.
    IfInMatch,
    /// `match` nested inside another `match`.
    NestedMatch,
    /// `match` inside an `if` branch.
    MatchInIf,
    /// Long `if/else if` chain exceeding the threshold.
    ElseChain,
    /// Attribute matching a forbidden pattern.
    ForbiddenAttribute { /// The pattern that matched.
        pattern: String },
    /// Type matching a forbidden pattern.
    ForbiddenType { /// The pattern that matched.
        pattern: String },
    /// Method call matching a forbidden pattern.
    ForbiddenCall { /// The pattern that matched.
        pattern: String },
    /// Macro matching a forbidden pattern.
    ForbiddenMacro { /// The pattern that matched.
        pattern: String },
    /// Use of the `else` keyword.
    ForbiddenElse,
    /// Use of an `unsafe` block.
    ForbiddenUnsafe,
    /// Dynamic dispatch (`Box<dyn T>`, `Arc<dyn T>`) in a return type.
    DynReturn,
    /// Dynamic dispatch (`&dyn T`, `Box<dyn T>`) in a function parameter.
    DynParam,
    /// `Vec<Box<dyn T>>` preventing cache locality.
    VecBoxDyn,
    /// Dynamic dispatch in a struct field.
    DynField,
    /// `.clone()` called inside a loop body.
    CloneInLoop,
    /// `HashMap`/`HashSet` using the default SipHash hasher.
    DefaultHasher,
    /// Disconnected type groups in a single file.
    MixedConcerns,
    /// `#[cfg(test)] mod` block embedded in a source file.
    InlineTests,
}

impl ViolationType {
    /// Returns the short code string used in output (e.g., `"max-depth"`).
    pub fn code(&self) -> &'static str {
        match self {
            Self::MaxDepth => "max-depth",
            Self::NestedIf => "nested-if",
            Self::IfInMatch => "if-in-match",
            Self::NestedMatch => "nested-match",
            Self::MatchInIf => "match-in-if",
            Self::ElseChain => "else-chain",
            Self::ForbiddenAttribute { .. } => "forbidden-attribute",
            Self::ForbiddenType { .. } => "forbidden-type",
            Self::ForbiddenCall { .. } => "forbidden-call",
            Self::ForbiddenMacro { .. } => "forbidden-macro",
            Self::ForbiddenElse => "forbidden-else",
            Self::ForbiddenUnsafe => "forbidden-unsafe",
            Self::DynReturn => "dyn-return",
            Self::DynParam => "dyn-param",
            Self::VecBoxDyn => "vec-box-dyn",
            Self::DynField => "dyn-field",
            Self::CloneInLoop => "clone-in-loop",
            Self::DefaultHasher => "default-hasher",
            Self::MixedConcerns => "mixed-concerns",
            Self::InlineTests => "inline-tests",
        }
    }

    /// Returns the check category name (e.g., `"nesting"`, `"dispatch"`).
    pub fn check_name(&self) -> &'static str {
        match self {
            Self::MaxDepth
            | Self::NestedIf
            | Self::IfInMatch
            | Self::NestedMatch
            | Self::MatchInIf
            | Self::ElseChain => "nesting",
            Self::ForbiddenAttribute { .. } => "forbid_attributes",
            Self::ForbiddenType { .. } => "forbid_types",
            Self::ForbiddenCall { .. } => "forbid_calls",
            Self::ForbiddenMacro { .. } => "forbid_macros",
            Self::ForbiddenElse => "forbid_else",
            Self::ForbiddenUnsafe => "forbid_unsafe",
            Self::DynReturn | Self::DynParam | Self::VecBoxDyn | Self::DynField => "dispatch",
            Self::CloneInLoop | Self::DefaultHasher => "performance",
            Self::MixedConcerns | Self::InlineTests => "structure",
        }
    }

    /// Returns the matched pattern for pattern-based violations, or `None`.
    pub fn pattern(&self) -> Option<&str> {
        match self {
            Self::ForbiddenAttribute { pattern }
            | Self::ForbiddenType { pattern }
            | Self::ForbiddenCall { pattern }
            | Self::ForbiddenMacro { pattern } => Some(pattern),
            _ => None,
        }
    }

    /// Returns the detailed rationale explaining why this check exists.
    pub fn rationale(&self) -> CheckRationale {
        match self {
            Self::MaxDepth => CheckRationale {
                problem: "Deeply nested code is hard to read, test, and modify. Each nesting level adds cognitive load. Bugs hide in deep branches.",
                fix: "Extract functions, use early returns, flatten with guard clauses.",
                exception: "Complex parsers or state machines may need deeper nesting locally.",
                llm_specific: false,
            },
            Self::NestedIf | Self::IfInMatch | Self::NestedMatch | Self::MatchInIf => CheckRationale {
                problem: "Conditional-in-conditional creates combinatorial complexity. A 2-branch if inside a 3-branch match is 6 paths. Hard to ensure all paths are tested.",
                fix: "Use tuple patterns `match (a, b) { ... }`, match guards `Some(x) if x > 0 => ...`, or extract to functions.",
                exception: "None. Refactoring is always possible.",
                llm_specific: false,
            },
            Self::ElseChain => CheckRationale {
                problem: "Long if/else if/else if chains are unordered match arms in disguise. Easy to miss cases, hard to verify exhaustiveness.",
                fix: "Use `match` on boolean tuples. Precedence becomes explicit, compiler checks exhaustiveness.",
                exception: "None. Any boolean chain can be refactored to a tuple match.",
                llm_specific: false,
            },
            Self::ForbiddenAttribute { .. } => CheckRationale {
                problem: "Silences warnings that indicate real problems. Dead code is maintenance burden. Unused variables often signal logic errors.",
                fix: "Remove dead code. Use `_` prefix for intentionally unused bindings. Address the underlying issue rather than suppressing.",
                exception: "Generated code, FFI bindings, conditional compilation.",
                llm_specific: true,
            },
            Self::ForbiddenType { .. } => CheckRationale {
                problem: "Certain type patterns indicate suboptimal design. Arc<String> has double indirection. Box<dyn Error> is superseded by better alternatives.",
                fix: "Use Arc<str> instead of Arc<String>. Use thiserror or anyhow instead of Box<dyn Error>.",
                exception: "When mutation methods are needed via Arc::make_mut(), or legacy API interop.",
                llm_specific: true,
            },
            Self::ForbiddenCall { .. } => CheckRationale {
                problem: ".unwrap() and .expect() panic on failure with no recovery. .clone() hides allocations.",
                fix: "Use `?` for propagation. Use .unwrap_or(), .unwrap_or_default() for defaults. Restructure ownership to avoid clone.",
                exception: "Human-authored code may use .unwrap() on provably infallible paths with documented invariants. Does not apply to LLM-generated code.",
                llm_specific: true,
            },
            Self::ForbiddenMacro { .. } => CheckRationale {
                problem: "panic!/todo!/unimplemented! crash at runtime. dbg!/println! are debug artifacts that shouldn't be committed.",
                fix: "Return Result instead of panicking. Use proper logging (tracing, log) for diagnostics. Implement functionality instead of stubbing.",
                exception: "Invariant assertions for bugs (not expected failures). CLI tools where stdout is the interface.",
                llm_specific: true,
            },
            Self::ForbiddenElse => CheckRationale {
                problem: "`else` creates implicit branches. `match` makes all branches explicit and compiler-checked.",
                fix: "Use `match` for multi-way branches. Use early return with guard clauses instead of if/else.",
                exception: "This is a style preference. Clippy recommends if/else for simple boolean conditions (match_bool lint). Disable with `forbid_else = false` if you disagree.",
                llm_specific: false,
            },
            Self::ForbiddenUnsafe => CheckRationale {
                problem: "`unsafe` bypasses Rust's safety guarantees. Memory corruption, undefined behavior, and security vulnerabilities become possible.",
                fix: "Use safe abstractions. Wrap unsafe in minimal, well-audited modules with safe public APIs.",
                exception: "FFI bindings, performance-critical code with proven safety invariants, implementing safe abstractions over unsafe primitives.",
                llm_specific: false,
            },
            Self::DynReturn => CheckRationale {
                problem: "Returning Box<dyn Trait> or Arc<dyn Trait> forces vtable dispatch on every call. The vtable lookup prevents inlining and all downstream optimizations.",
                fix: "Use enum dispatch for a closed set of types. Use `impl Trait` when the caller doesn't need to store heterogeneously. Use a generic type parameter when the concrete type varies per call site.",
                exception: "Plugin systems or FFI boundaries where the set of concrete types is truly open-ended and unknown at compile time.",
                llm_specific: true,
            },
            Self::DynParam => CheckRationale {
                problem: "Accepting &dyn Trait or Box<dyn Trait> as a parameter forces vtable dispatch per call. The compiler cannot monomorphize or inline the callee's methods.",
                fix: "Use a generic parameter `T: Trait` or `impl Trait` to enable monomorphization. The compiler generates specialized code for each concrete type, enabling inlining.",
                exception: "When the function is called with many distinct concrete types and binary size is a concern, or when storing heterogeneous collections.",
                llm_specific: true,
            },
            Self::VecBoxDyn => CheckRationale {
                problem: "Vec<Box<dyn Trait>> incurs per-element heap allocation, vtable dispatch on every access, and scattered memory that defeats cache prefetching.",
                fix: "Use an enum wrapping the known concrete types. Elements are stored inline in the Vec with no vtable and no per-element allocation.",
                exception: "Plugin systems where concrete types are loaded at runtime and cannot be enumerated at compile time.",
                llm_specific: true,
            },
            Self::DynField => CheckRationale {
                problem: "A Box<dyn Trait> or Arc<dyn Trait> struct field permanently commits every method call on that field to vtable dispatch. This prevents inlining for the lifetime of the struct.",
                fix: "Make the struct generic over the trait: `struct Foo<T: Trait> { field: T }`. The compiler monomorphizes each instantiation, enabling static dispatch and inlining.",
                exception: "When the struct must hold different concrete types at different times, or when the concrete type is determined at runtime (e.g., configuration-driven).",
                llm_specific: true,
            },
            Self::CloneInLoop => CheckRationale {
                problem: ".clone() inside a loop body means N heap allocations where N is the iteration count. LLMs add .clone() to satisfy the borrow checker without considering the per-iteration cost.",
                fix: "Borrow instead of cloning. Use Cow<T> for conditional ownership. Use Rc/Arc for shared ownership. Restructure to move ownership before the loop.",
                exception: "When the cloned value is mutated independently per iteration and borrowing is not possible.",
                llm_specific: true,
            },
            Self::DefaultHasher => CheckRationale {
                problem: "HashMap/HashSet default to SipHash, designed for HashDoS resistance. SipHash is 2-5x slower than FxHash or AHash for typical keys (integers, short strings).",
                fix: "Use rustc_hash::FxHashMap for integer keys. Use ahash::AHashMap for general-purpose fast hashing. Specify the hasher explicitly: HashMap<K, V, S>.",
                exception: "When keys come from untrusted input (network, user-provided) and HashDoS resistance is required.",
                llm_specific: true,
            },
            Self::MixedConcerns => CheckRationale {
                problem: "Disconnected type groups in a single file indicate mixed concerns. Types that share no fields, trait bounds, or function signatures belong in separate modules.",
                fix: "Split the file along connected components. Each group of related types becomes its own module.",
                exception: "Re-export modules or files that intentionally collect small, independent items (e.g., error enums).",
                llm_specific: true,
            },
            Self::InlineTests => CheckRationale {
                problem: "Test modules embedded in source files mix production code with test code. This inflates source files and makes test organization harder to navigate.",
                fix: "Move tests to the tests/ directory as integration tests, or to a separate test file alongside the source.",
                exception: "Small utility modules where colocated unit tests are preferred for locality.",
                llm_specific: true,
            },
        }
    }
}

impl fmt::Display for ViolationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code())
    }
}

/// A single violation found during analysis.
#[derive(Debug, Clone)]
pub struct Violation {
    /// What kind of violation this is.
    pub violation_type: ViolationType,
    /// Path to the file containing the violation.
    pub file_path: String,
    /// Line number (1-based).
    pub line: usize,
    /// Column number (1-based).
    pub column: usize,
    /// Human-readable description of the violation.
    pub message: String,
}

impl Violation {
    /// Creates a new violation at the given source location.
    pub fn new(
        violation_type: ViolationType,
        file_path: String,
        line: usize,
        column: usize,
        message: String,
    ) -> Self {
        Self {
            violation_type,
            file_path,
            line,
            column,
            message,
        }
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}: {}: {}",
            self.file_path, self.line, self.column, self.violation_type, self.message
        )
    }
}
