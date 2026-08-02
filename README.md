[![crates.io](https://img.shields.io/crates/v/pedant)](https://crates.io/crates/pedant)
[![docs.rs](https://img.shields.io/docsrs/pedant-core)](https://docs.rs/pedant-core)
[![CI](https://github.com/jostled-org/pedant/actions/workflows/ci.yml/badge.svg)](https://github.com/jostled-org/pedant/actions/workflows/ci.yml)
[![license](https://img.shields.io/crates/l/pedant)](LICENSE-MIT)

**pedant** maps what code can do — network access, filesystem operations, crypto, process execution — across Rust, Python, JavaScript/TypeScript, Go, and Bash. It hashes dependency source on every build and alerts when capabilities change. A supply chain attack that adds `file_read` or `env_access` to a library is caught before the compromised code runs.

## What it catches

A dependency update adds environment variable exfiltration to a library that previously only did HTTP:

```
$ pedant diff baseline.json current.json
{
  "added": [
    {"capability": "env_access", "evidence": "std::env::var"},
    {"capability": "file_read", "evidence": "std::fs::read_to_string"}
  ],
  "new_capabilities": ["env_access", "file_read"]
}
```

A build script phones home during compilation. Point pedant at the crate's sources — it discovers `build.rs` from the crate root itself:

```
$ pedant gate src
deny: build-script-network — Build scripts should not make network requests
warn: build-script-exec — Build scripts spawning processes is common (cc, pkg-config) but risky
deny: build-script-download-exec — Download-and-execute in build script — classic supply chain attack
```

Nesting three levels deep in a match arm:

```
$ pedant check -d 2 src/lib.rs
src/lib.rs:3:17: nested-match: nested match expression, consider tuple matching
src/lib.rs:4:21: max-depth: nesting depth 3 exceeds limit of 2
src/lib.rs:4:21: nested-match: nested match expression, consider tuple matching

Found 3 violation(s)
```

## Quick start

```bash
# Install
cargo install pedant

# Scan a project for capabilities — directories are recursed
pedant capabilities src scripts

# Check for suspicious patterns
pedant gate src

# Set up CI supply chain monitoring (see examples/supply-chain-check.md)
```

Migrating from the old flat flag CLI? See [docs/migrating-from-flat-cli.md](docs/migrating-from-flat-cli.md).

## GitHub Actions

Three composite actions. Each builds pedant from the pinned action source — no registry fetch, one trust boundary.

```yaml
- uses: jostled-org/pedant/.github/actions/pedant-check@<commit>   # structure and style
  with:
    paths: src
- uses: jostled-org/pedant/.github/actions/pedant-gate@<commit>    # capability gate rules
  with:
    paths: src
- uses: jostled-org/pedant/.github/actions/supply-chain-check@<commit>
  with:
    baseline-path: .pedant/baselines
```

They default to `--format github`, so findings arrive as annotations on the pull request rather than log lines. `deny` fails the step; `warn` annotates and passes. The same format is available from the CLI:

```
$ pedant check --format github src
::error file=src/nested.rs,line=4,col=21,title=max-depth::nesting depth 3 exceeds limit of 2

$ pedant gate --format github src
::error title=build-script-download-exec::Download-and-execute in build script — classic supply chain attack
```

Violations anchor to their source location. Gate verdicts judge a whole capability profile and have no location, so they attach to the run.

## CI Supply Chain Check

The included GitHub Action hashes every dependency's source and compares against stored baselines on every build. It detects:

- **Tag-swap attacks** — same version number, different content (hash mismatch)
- **Capability drift** — new capabilities appearing in a dependency update
- **New unaudited dependencies** — dependencies with no existing baseline

```yaml
# .github/workflows/ci.yml
jobs:
  supply-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: dtolnay/rust-toolchain@a54c7afe936fefeb4456b2dd8068152669aa8211 # stable
      - uses: jostled-org/pedant/.github/actions/supply-chain-check@<commit> # pin to commit
        with:
          baseline-path: .pedant/baselines
          fail-on: new-dependency
```

`new-dependency` fails when a crate enters the tree or gains a capability, but not on a routine version bump — a new or tampered dependency trips CI until you review it and run `pedant supply-chain update`. `hash-mismatch` (the action default) only re-checks content that Cargo.lock already verifies, and `new-capability` misses a wholly-new crate; see [examples/supply-chain-check.md](examples/supply-chain-check.md) for the trade-offs.

Pedant is built from the same pinned commit as the action — no registry fetch, one trust boundary. That example covers setup and baseline management.

## Capability Detection

```bash
# Rust, Python, JS/TS, Go, Bash — language detected automatically
pedant capabilities src scripts deploy

# Attestation: capability profile + SHA-256 source hash + crate identity
pedant attestation --crate-name my-crate --crate-version 0.1.0 src

# Diff two profiles or attestations
pedant diff old.json new.json
```

Directories are searched recursively for any file pedant recognizes. Build directories (those carrying `CACHEDIR.TAG`, as cargo writes into `target/`), `node_modules`, and dot-directories are skipped; a file named explicitly is always analyzed.

| Capability | What triggers it |
|---|---|
| `network` | `std::net`, `reqwest`, `curl`, `fetch()`, `net/http`, URL literals |
| `file_read` | `std::fs`, `open()`, `os.Open()` |
| `file_write` | `std::fs::write`, `cp`, `mv`, `rm` |
| `process_exec` | `std::process`, `subprocess`, `exec`, `bash -c` |
| `env_access` | `std::env::var`, `process.env`, `os.Getenv`, `export` |
| `unsafe_code` | `unsafe` blocks, `unsafe fn`, `unsafe impl` |
| `ffi` | `extern` blocks, `ctypes`, `import "C"` |
| `crypto` | `ring`, `openssl`, PEM blocks, hex keys, credential prefixes |
| `system_time` | `SystemTime`, `chrono`, `time` |
| `proc_macro` | `#[proc_macro]`, `#[proc_macro_derive]` |

Gate rules evaluate per language group by default. Use `--cross-language` to merge all findings for combined evaluation.

See [examples/capability-detection.md](examples/capability-detection.md) for the full guide: output format, all 24 gate rules, multi-language details, string literal analysis, attestation, and diffing.

## Style Checks (Rust)

32 checks across five categories. Nesting checks run by default. Everything else needs `.pedant.toml`: most are off until you enable them, while the rule-driven checks (`item-visibility-policy`, `flat-module-family`, `feature-boundary`) are on by default but stay silent until you give them rules.

```bash
pedant check src                    # a directory — pedant recurses it
pedant check src crates             # several roots, de-duplicated
pedant check -d 2 src/lib.rs        # one file, custom depth limit
pedant list-checks                  # see all checks
pedant explain max-depth            # detailed rationale
```

Pass directories rather than a `**` glob. Recursion happens inside pedant, so every caller gets the same rules; a `**` glob depends on your shell (bash needs `globstar`, and silently matches only one level deep without it).

| Category | Checks |
|----------|--------|
| Nesting | `max-depth`, `nested-if`, `if-in-match`, `nested-match`, `match-in-if`, `else-chain` |
| Forbidden patterns | `forbidden-attribute`, `forbidden-type`, `forbidden-call`, `forbidden-macro`, `forbidden-else`, `forbidden-unsafe` |
| Performance & dispatch | `dyn-return`, `dyn-param`, `vec-box-dyn`, `dyn-field`, `clone-in-loop`, `default-hasher` |
| Structure (per file) | `mixed-concerns`, `inline-tests`, `let-underscore-result`, `high-param-count`, `long-function-body`, `module-root-definitions`, `large-source-file`, `high-method-count`, `item-visibility-policy`, `ungated-test-api` |
| Structure (whole project) | `conflicting-module-root`, `flat-module-family`, `feature-boundary`, `scattered-inherent-impl` |
| Naming | `generic-naming` |

The project-level checks read the source tree and Cargo metadata rather than a single file, so run them from the workspace root and give them the whole tree — `feature-boundary` shells out to `cargo metadata`.

`high-method-count` spans both rows. Given a whole crate it counts a type's inherent methods across every file, so splitting an `impl` in two does not duck the ceiling; given one file it counts what that file shows. Aggregation is deliberately conservative — a type name is totalled only when the crate defines it in exactly one place. `#[cfg]`-gated impls are grouped by predicate and the type is measured against its worst build (everything unconditional plus the single richest alternative), so mutually exclusive platform impls never sum into a phantom god-object, yet a `#[cfg(feature = "…")]` on a default-on feature cannot hide one either.

Violations carry a severity. `deny` fails the run; `warn` is reported but exits 0. Every check denies by default; only checks with an explicit warning tier, like `large-source-file`, emit warnings.

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

## Semantic Analysis (Rust)

With the `semantic` feature, pedant resolves types through aliases using rust-analyzer and enables data flow analysis: taint tracking (environment variables flowing to network sinks), quality checks (dead stores, discarded results), performance checks (unnecessary clones, allocation in loops), and concurrency checks (lock guards across await points).

```bash
cargo install pedant --features semantic
pedant gate --semantic src/**/*.rs
```

## MCP Server

`pedant-mcp` exposes analysis as MCP tools for AI agents.

```bash
cargo install pedant-mcp
claude mcp add --transport stdio --scope user pedant -- pedant-mcp
```

Tools: `query_capabilities`, `query_gate_verdicts`, `query_violations`, `search_by_capability`, `explain_finding`, `audit_crate`, `find_structural_duplicates`.

### pedant-snippet

`pedant-snippet` returns the source declaration enclosing one file location, byte for byte. It serves the same operation as a CLI and as a stdio MCP server. It parses Rust, Python, JavaScript, TypeScript, TSX, Go, and Bash.

```bash
cargo install pedant-snippet
claude mcp add --transport stdio --scope user pedant-snippet -- pedant-snippet mcp
```

The CLI takes the location and the output shape:

```bash
pedant-snippet extract --file src/lib.rs --line 42 --column 9 --format text
```

`--column` is optional and `--format` defaults to `json`. Tool: `enclosing_unit`.

## Configuration

```toml
# .pedant.toml
max_depth = 2
forbid_else = true
check_clone_in_loop = true

# Structural checks, off by default — thresholds shown are the shipped defaults
check_long_function_body = true
max_function_body_lines = 120
check_large_source_file = true
source_file_warn_lines = 500       # warn tier: reported, exits 0
source_file_deny_lines = 1000      # deny tier: fails the run
check_high_method_count = true
max_methods = 40
check_module_root_definitions = true

[forbid_calls]
enabled = true
patterns = [".unwrap()", ".expect(*)"]

[gate]
build-script-exec = false          # disable a rule
env-access-network = "warn"        # override severity

[overrides."tests/**"]
max_depth = 5

[overrides."tests/**".forbid_calls]
enabled = false
```

Thresholds also have CLI flags (`--max-function-body`, `--max-methods`, `--max-source-file-lines`, `--warn-source-file-lines`), and passing one enables its check. Every check has a `--no-<check>` toggle.

Config loads from `.pedant.toml` (project) or `~/.config/pedant/config.toml` (global). Project wins. See [examples/](examples/) for full configs.

## License

[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
