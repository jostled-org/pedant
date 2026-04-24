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

A build script phones home during compilation:

```
$ pedant gate build.rs
::error:: build-script-network: build script has network access (deny)
::error:: build-script-download-exec: build script downloads and executes (deny)
```

Nesting three levels deep in a match arm:

```
$ pedant check -d 2 src/lib.rs
src/lib.rs:5:17: if-in-match: if inside match arm, consider match guard
src/lib.rs:5:17: max-depth: nesting depth 3 exceeds limit of 2
```

## Quick start

```bash
# Install
cargo install pedant

# Scan a project for capabilities
pedant capabilities src/**/*.rs scripts/*.py

# Check for suspicious patterns
pedant gate src/**/*.rs

# Set up CI supply chain monitoring (see examples/supply-chain-check.md)
```

Migrating from the old flat flag CLI? See [docs/migrating-from-flat-cli.md](docs/migrating-from-flat-cli.md).

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
          fail-on: hash-mismatch
```

Pedant is built from the same pinned commit as the action — no registry fetch, one trust boundary. See [examples/supply-chain-check.md](examples/supply-chain-check.md) for setup, baseline management, and configuration.

## Capability Detection

```bash
# Rust, Python, JS/TS, Go, Bash — language detected automatically
pedant capabilities src/**/*.rs scripts/*.py deploy/*.sh

# Attestation: capability profile + SHA-256 source hash + crate identity
pedant attestation --crate-name my-crate --crate-version 0.1.0 src/**/*.rs

# Diff two profiles or attestations
pedant diff old.json new.json
```

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

23 checks across five categories. Nesting checks run by default; everything else requires a `.pedant.toml` config.

```bash
pedant check src/**/*.rs            # check files
pedant check -d 2 src/lib.rs        # custom depth limit
pedant list-checks                  # see all checks
pedant explain max-depth            # detailed rationale
```

| Category | Checks |
|----------|--------|
| Nesting | `max-depth`, `nested-if`, `if-in-match`, `nested-match`, `match-in-if`, `else-chain` |
| Forbidden patterns | `forbidden-attribute`, `forbidden-type`, `forbidden-call`, `forbidden-macro`, `forbidden-else`, `forbidden-unsafe` |
| Performance & dispatch | `dyn-return`, `dyn-param`, `vec-box-dyn`, `dyn-field`, `clone-in-loop`, `default-hasher` |
| Structure | `mixed-concerns`, `inline-tests`, `let-underscore-result`, `high-param-count` |
| Naming | `generic-naming` |

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

## Configuration

```toml
# .pedant.toml
max_depth = 2
forbid_else = true
check_clone_in_loop = true

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

Config loads from `.pedant.toml` (project) or `~/.config/pedant/config.toml` (global). Project wins. See [examples/](examples/) for full configs.

## License

[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
