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

# Judge one Cargo project against its declared module boundaries
pedant gate --project .

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

Violations anchor to their source location. Capability gate verdicts judge a whole profile and have no location, so they attach to the run. Module-boundary verdicts name a subject and anchor to it when it has source bytes.

## Module Boundary Gate

`pedant gate` takes exactly one input mode: a file list, `--stdin`, or one Cargo project.

```bash
pedant gate src/**/*.rs            # capability and data-flow rules
pedant gate --stdin                # one source on standard input
pedant gate --project .            # module-boundary rules over a Cargo project
```

`--project` conflicts with files, `--stdin`, and `--cross-language`. It selects every library, binary, and build-script target of every workspace member, judges each one separately, and labels the result `<package-dir-or-dot>#<kind>:<target-name>`. Examples, integration tests, benchmarks, and non-member path dependencies are not independent roots.

Judgment reads only relationships the selected tier proved: resolved `Call`, `Import`, `Implementation`, and `Reference` edges. Ambiguous candidates and Cargo dependency edges never support a blocking claim.

| Rule | Default | Fires when |
|---|---|---|
| `large-scc` | `warn` | a cyclic component has more than 8 members |
| `boundary-crossing-scc` | `deny` | a cycle runs through more than one declared module |
| `misplaced-symbol` | `warn` | a symbol has at least 3 foreign edges and at least 60% of its outgoing edges leave its module |
| `low-module-cohesion` | `warn` | a module has at least 4 outgoing edges and keeps under 50% of them internal |

Configure them under `[gate.module-boundary]`. Each rule key takes `false`, `true`, or a severity name. `enabled = false` disables all four without disabling project or analysis failures.

```toml
[gate.module-boundary]
enabled = true
boundary-crossing-scc = "deny"
misplaced-symbol = "warn"

max-scc-members = 8
misplaced-symbol-min-foreign-edges = 3
misplaced-symbol-min-affinity-percent = 60
low-module-cohesion-min-outgoing-edges = 4
low-module-cohesion-min-percent = 50

max-nodes = 250000
max-references = 1000000
max-edges = 1000000
max-selected-edges = 1000000
```

Project mode resolves configuration in one order: an explicit `--config` path, read as you wrote it relative to the working directory; then `<project-root>/.pedant.toml`; then the global config; then the defaults. A missing file advances to the next source. Any other failure is fatal.

Text and GitHub state the tier and every analyzed target before any verdict. JSON carries both in the same envelope. A clean run stays observable in every format.

```
$ pedant gate --project .
analysis-tier: syntactic
target: ".#lib:demo"
deny: boundary-crossing-scc — cycle crosses declared module partitions; target=".#lib:demo"; subject={"ordinal":4,"label":"scc::demo::left::up","location":{"path":"src/left.rs","line":2,"column":8}}; measurement={"kind":"component","cyclic":true,"members":[...],"partitions":[...]}
```

JSON appends `analyzed_targets` after the existing envelope fields and attaches the triggering evidence to each verdict. GitHub emits one workflow notice per run, then one annotation per verdict. File and stdin output keeps its exact previous bytes, because absent evidence is omitted.

A `deny` verdict exits 1, advisory-only evidence exits 0, and any project, snapshot, resolution, graph, analysis, projection, or write failure exits 2 with no verdict and no success payload.

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

33 checks across five categories. Nesting checks run by default. Everything else needs `.pedant.toml`: most are off until you enable them, while the rule-driven checks (`item-visibility-policy`, `flat-module-family`, `feature-boundary`) are on by default but stay silent until you give them rules.

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

In project mode `--semantic` is strict: pedant loads one context at the project root and resolves every target through it, or exits 2. It never reports a syntactic success for an explicitly semantic run.

## MCP Server

`pedant-mcp` exposes analysis as MCP tools for AI agents.

```bash
cargo install pedant-mcp
claude mcp add --transport stdio --scope user pedant -- pedant-mcp
```

Tools: `query_capabilities`, `query_gate_verdicts`, `query_violations`, `search_by_capability`, `explain_finding`, `audit_crate`, `find_structural_duplicates`.

### pedant-snippet

`pedant-snippet` indexes one repository and answers navigation questions about it. It parses Rust, Python, JavaScript, TypeScript, TSX, Go, and Bash. The server rebuilds the index as the tree changes, so an answer describes the repository as it is.

```bash
cargo install pedant-snippet
claude mcp add --transport stdio --scope user pedant-snippet -- pedant-snippet mcp --root .
```

Eight questions, served as CLI commands and as MCP tools. With `mcp`, which serves the other eight over stdio, that is nine CLI commands and eight MCP tools — one library operation behind each pair.

| Command | Tool | Answers |
| --- | --- | --- |
| `list-projects` | `list_projects` | every project the index resolved |
| `search` | `search_symbols` | every named structure a query selects |
| `outline` | `outline_file` | one file's structure forest, in source order |
| `read` | `read_structure` | one structure and its exact source |
| `at` | `structure_at` | the narrowest structure containing one point |
| `relations` | `query_relations` | one declaration's graph neighborhood |
| `path` | `find_path` | the shortest route between two declarations |
| `graph` | `analyze_graph` | one derived answer about a project graph |

```bash
pedant-snippet at src/lib.rs 42 --column 9 --format text
pedant-snippet search make --mode exact
```

`--root` defaults to the working directory and `--format` defaults to `json`. Both transports call the same library operation and serialize what it returns, so a CLI answer and a tool answer to one question are the same bytes.

Every language and both graph producers are default features, so an installed binary answers all eight questions. A build that selects no graph producer serves the first five and advertises no others.

Rust and Go projects are graph-backed, so `relations`, `path`, and `graph` answer from a resolved project graph. JavaScript, TypeScript, Python, and Bash are syntax-only: search, outline, read, and point lookup are complete for them, and a graph request over one of them returns typed syntax-only coverage rather than an empty answer that reads as "no callers". Their graph extractors are later work and change no command, tool, or index.

The index reads source files and does nothing else. It writes no file, spawns no process, opens no socket, and invokes no language server or toolchain, so it is safe to point at a repository you did not author.

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

Thresholds also have CLI flags (`--max-function-body`, `--max-methods`, `--max-source-file-lines`, `--warn-source-file-lines`), and passing one enables its check. Fifteen checks carry a `--no-<check>` flag that turns them off; `pedant check --help` lists them.

Config loads from `.pedant.toml` (project) or `~/.config/pedant/config.toml` (global). Project wins. See [examples/](examples/) for full configs.

## License

[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
