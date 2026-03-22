[![crates.io](https://img.shields.io/crates/v/pedant)](https://crates.io/crates/pedant)
[![docs.rs](https://img.shields.io/docsrs/pedant-core)](https://docs.rs/pedant-core)
[![CI](https://github.com/jostled-org/pedant/actions/workflows/ci.yml/badge.svg)](https://github.com/jostled-org/pedant/actions/workflows/ci.yml)
[![license](https://img.shields.io/crates/l/pedant)](LICENSE-MIT)

You put "never use unwrap in production code" in your CLAUDE.md. Your AI assistant wrote `.unwrap()` anyway. Clippy catches it at compile time. pedant catches it at write time, before the code enters your project. Style rules in system prompts compete with training data, and training data wins. pedant enforces the rules your AI agent can't reliably follow.

**pedant** is a Rust linter and security analyzer. It enforces style rules too subjective for Clippy, detects what a crate can do (capabilities), flags suspicious capability combinations (gate rules), and exposes all of this via an MCP server for AI agents.

## Proof

Given this file:

```rust
fn run(x: Option<i32>) {
    if let Some(v) = x {
        match v {
            1 => {
                if v > 0 {
                    println!("ok");
                }
            }
            _ => {}
        }
    }
}
```

```
$ pedant -d 2 example.rs
example.rs:3:9: match-in-if: match inside if, consider restructuring
example.rs:5:17: if-in-match: if inside match arm, consider match guard
example.rs:5:17: max-depth: nesting depth 3 exceeds limit of 2

Found 3 violation(s)
```

All three pass `cargo check` and `cargo clippy`.

## Installation

```bash
cargo install pedant
```

## Usage

pedant has four modes: **linting** enforces style rules, **capability detection** audits what a crate can do, **gate rules** flag suspicious capability combinations, and an **MCP server** exposes all of this to AI agents.

### Linting

```bash
# Check files
pedant src/**/*.rs

# Custom depth limit
pedant -d 2 src/lib.rs

# Pipe generated code
echo "$generated_code" | pedant --stdin -f json
```

Exit codes: `0` clean, `1` violations, `2` error.

To run pedant as a [Claude Code hook](examples/pedant-claude-code-hook.md) that blocks AI-generated code on every edit:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [{ "type": "command", "command": "~/.claude/hooks/pedant-check.sh" }]
      }
    ]
  }
}
```

### Capability Detection

```bash
# Scan for capabilities (network, filesystem, unsafe, FFI, crypto, etc.)
pedant --capabilities src/**/*.rs

# Attestation (adds source hash and crate identity for reproducibility)
pedant --attestation --crate-name my-crate --crate-version 0.1.0 src/**/*.rs

# Diff two profiles or attestations
pedant --diff old.json new.json
```

Build scripts (`build.rs`) are automatically discovered and analyzed. Findings from build scripts are tagged with `"build_script": true` in the JSON output, distinguishing compile-time capabilities from runtime capabilities.

Exit codes for `--diff`: `0` no changes, `1` differences found, `2` error.

### Gate Rules

```bash
# Evaluate security rules against capability profile
pedant --gate src/**/*.rs

# Combine with attestation
pedant --gate --attestation --crate-name my-crate --crate-version 0.1.0 src/**/*.rs
```

Gate rules flag suspicious capability combinations — build scripts with network access, proc macros spawning processes, embedded key material with network capability. 9 built-in rules with configurable severity.

Exit codes: `0` clean or warn-only, `1` deny-level verdict fired, `2` error.

Configure in `.pedant.toml`:

```toml
[gate]
# Disable a rule
build-script-exec = false

# Override severity (deny/warn/info)
env-access-network = "warn"
```

### MCP Server

```bash
# Start the MCP server (indexes workspace, serves queries via stdio)
pedant-mcp
```

`pedant-mcp` exposes pedant's analysis as MCP tools for AI agents. It indexes the workspace on startup, watches for file changes, and serves queries:

- `query_capabilities` — list capability findings for a crate, file, or workspace
- `query_gate_verdicts` — evaluate gate rules for a crate or workspace
- `query_violations` — list style violations with optional filtering
- `search_by_capability` — find crates matching a capability pattern (e.g., "network + crypto")
- `explain_finding` — get rationale for a specific check
- `audit_crate` — full security summary: capabilities, verdicts, violations

See the [capability detection guide](examples/capability-detection.md) for output format, supported capabilities, attestation details, and diffing.

## Configuration

pedant loads config from two locations, in priority order:

1. **Project** — `.pedant.toml` in the current directory
2. **Global** — `~/.config/pedant/config.toml` (or `$XDG_CONFIG_HOME/pedant/config.toml`)

Project config wins. If neither exists, built-in defaults apply. Use `-c <path>` to specify an explicit config file.

A minimal config that catches common AI-generated patterns:

```toml
max_depth = 2
forbid_else = true
forbid_unsafe = true
check_clone_in_loop = true
check_inline_tests = true

[check_naming]
enabled = true

[forbid_calls]
enabled = true
patterns = [".unwrap()", ".expect(*)"]

[forbid_macros]
enabled = true
patterns = ["panic!", "todo!", "dbg!", "println!"]

# Relax rules for tests
[overrides."tests/**"]
max_depth = 5

[overrides."tests/**".forbid_calls]
enabled = false

[overrides."tests/**".forbid_macros]
enabled = false
```

Scalar keys must appear before `[table]` sections — TOML assigns bare keys after a header to that table.

See `examples/` for a full global config and a project-level override.

## Checks

22 checks across five categories. Nesting checks run by default. Everything else requires a config file.

| Category | Checks |
|----------|--------|
| Nesting | `max-depth`, `nested-if`, `if-in-match`, `nested-match`, `match-in-if`, `else-chain` |
| Forbidden patterns | `forbidden-attribute`, `forbidden-type`, `forbidden-call`, `forbidden-macro`, `forbidden-else`, `forbidden-unsafe` |
| Performance & dispatch | `dyn-return`, `dyn-param`, `vec-box-dyn`, `dyn-field`, `clone-in-loop`, `default-hasher` |
| Structure | `mixed-concerns`, `inline-tests`, `let-underscore-result` |
| Naming | `generic-naming` |

Run `pedant --list-checks` to see all checks, or `pedant --explain <check>` for detailed rationale and fix guidance.

## Semantic Analysis

With the `semantic` feature enabled, pedant resolves types through aliases using rust-analyzer's analysis engine (`ra_ap_ide`). This eliminates false positives in clone-in-loop, refcounted detection, and type classification checks.

```bash
# Build with semantic support
cargo install pedant --features semantic

# Run with type resolution (requires Cargo workspace)
pedant --semantic src/**/*.rs
```

When `--semantic` is active, the attestation's `analysis_tier` is set to `"semantic"` instead of `"syntactic"`, signaling higher-confidence results.

## License

[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
