# pedant

A fast, opinionated Rust linter for keeping AI-generated code clean.

## The Problem

LLMs write code that compiles but violates best practices. Common patterns:

- **Nested conditionals** — `if` inside `if`, `match` inside `match`
- **Panic-prone code** — `.unwrap()`, `.expect()`, `todo!()`
- **Silenced warnings** — `#[allow(dead_code)]`, `#[allow(clippy::*)]`
- **Lazy cloning** — `.clone()` to satisfy the borrow checker
- **Debug artifacts** — `dbg!()`, `println!()` left in production code
- **Mixed concerns** — unrelated types dumped into a single file

These patterns pass `cargo check` and often slip through code review. pedant catches them.

## Why pedant?

**Built for LLM workflows.** Designed to validate AI-generated code before it enters your codebase:

- **Stdin support** — pipe generated code directly: `echo "$code" | pedant --stdin`
- **JSON output** — structured violations for automated pipelines
- **Exit codes** — `0` clean, `1` violations, `2` error
- **Fast** — single-pass AST analysis, no type inference

**Catches what Clippy misses.** Clippy focuses on correctness. pedant enforces taste:

- Configurable nesting depth limits
- Branch-in-branch detection (all combinations of `if`/`match`)
- Else-chain detection for long `if/else if` sequences
- Mixed concerns via type-graph connectivity analysis
- Per-path overrides for tests and generated code

## Installation

```bash
cargo install pedant
```

## Usage

```bash
# Check files
pedant src/*.rs
pedant -d 2 src/lib.rs          # custom max depth
pedant -f json src/              # JSON output for tooling

# Validate LLM output
echo "$generated_code" | pedant --stdin -f json

# CI integration
if ! pedant src/; then
    echo "pedant violations found"
    exit 1
fi
```

## LLM Integration

### Pre-commit validation

```bash
#!/bin/bash
pedant $(git diff --cached --name-only -- '*.rs')
```

### In automated pipelines

```bash
# Validate before accepting generated code
pedant --stdin -f json <<< "$llm_output"
if [ $? -eq 1 ]; then
    # feed violations back to LLM for correction
fi
```

## Checks

| Check | Flag to disable | Description |
|-------|-----------------|-------------|
| `max-depth` | `-d N` | Nesting exceeds limit (default: 3) |
| `nested-if` | `--no-nested-if` | `if` inside `if` |
| `if-in-match` | `--no-if-in-match` | `if` inside match arm |
| `nested-match` | `--no-nested-match` | `match` inside `match` |
| `match-in-if` | `--no-match-in-if` | `match` inside `if` |
| `else-chain` | `--no-else-chain` | Long `if/else if` chains (3+) |

### Pattern checks (config file only)

| Check | Config key | Description |
|-------|-----------|-------------|
| `forbidden-attribute` | `forbid_attributes` | Banned attributes (e.g., `allow(dead_code)`) |
| `forbidden-type` | `forbid_types` | Banned type patterns (e.g., `Arc<String>`) |
| `forbidden-call` | `forbid_calls` | Banned method calls (e.g., `.unwrap()`) |
| `forbidden-macro` | `forbid_macros` | Banned macros (e.g., `panic!`, `dbg!`) |
| `forbidden-else` | `forbid_else` | Use of `else` keyword |
| `forbidden-unsafe` | `forbid_unsafe` | Use of `unsafe` blocks |

### Performance and dispatch checks (off by default)

| Check | Config key | Description |
|-------|-----------|-------------|
| `dyn-return` | `check_dyn_return` | `Box<dyn T>` / `Arc<dyn T>` in return types |
| `dyn-param` | `check_dyn_param` | `&dyn T` / `Box<dyn T>` in function parameters |
| `vec-box-dyn` | `check_vec_box_dyn` | `Vec<Box<dyn T>>` anywhere |
| `dyn-field` | `check_dyn_field` | `Box<dyn T>` / `Arc<dyn T>` in struct fields |
| `clone-in-loop` | `check_clone_in_loop` | `.clone()` inside loop bodies |
| `default-hasher` | `check_default_hasher` | `HashMap`/`HashSet` with default SipHash |

### Structure checks (off by default)

| Check | Config key | Description |
|-------|-----------|-------------|
| `mixed-concerns` | `check_mixed_concerns` | Disconnected type groups in a single file |
| `inline-tests` | `check_inline_tests` | `#[cfg(test)] mod tests` embedded in source files |

Use `pedant --explain <CHECK>` for detailed rationale and fix guidance.

## Configuration

pedant loads config from two locations, in order of priority:

1. **Project config** — `.pedant.toml` in the current directory
2. **Global config** — `$XDG_CONFIG_HOME/pedant/config.toml` (defaults to `~/.config/pedant/config.toml`)

If a project config exists, it is used and the global config is ignored. If neither exists, built-in defaults apply. Use `-c <path>` to specify an explicit config file.

The global config is where you set your personal defaults (coding style preferences, which checks to enable). The project config overrides those defaults for a specific repo.

```toml
# All scalar keys must appear before any [table] sections.
# TOML assigns bare keys after a [table] header to that table.

max_depth = 3
check_nested_if = true
check_if_in_match = true
check_nested_match = true
check_match_in_if = true
check_else_chain = true
else_chain_threshold = 3
forbid_else = false
forbid_unsafe = true

# Performance and dispatch checks — off by default
check_dyn_return = false
check_dyn_param = false
check_vec_box_dyn = false
check_dyn_field = false
check_clone_in_loop = false
check_default_hasher = false

# Structure checks — off by default
check_mixed_concerns = false
check_inline_tests = false

# Pattern checks — disabled by default, enable with patterns
[forbid_attributes]
enabled = true
patterns = ["allow(dead_code)", "allow(clippy::*)"]

[forbid_types]
enabled = true
patterns = ["Arc<String>", "Arc<Vec<*>>", "Box<dyn*Error*>"]

[forbid_calls]
enabled = true
patterns = [".unwrap()", ".expect(*)", ".clone()"]

[forbid_macros]
enabled = true
patterns = ["panic!", "todo!", "dbg!", "println!", "eprintln!"]

# Per-path overrides
[overrides."tests/**"]
max_depth = 4

[overrides."**/generated.rs"]
enabled = false
```

## Exit Codes

- `0` - No violations
- `1` - Violations found
- `2` - Error (file not found, parse error)
