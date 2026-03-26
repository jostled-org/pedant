# Capability Detection

Pedant detects what a crate *can do* — network access, filesystem operations, unsafe code, cryptography — by scanning imports, function signatures, attributes, and string literals. Capability findings enumerate behavior without judging it.

## Usage

```bash
# Scan files for capabilities
pedant --capabilities src/**/*.rs

# Pipe source and get JSON output
echo 'use std::net::TcpStream;' | pedant --stdin --capabilities

# Combine with linting
pedant --capabilities -f json src/lib.rs
```

## Capabilities

| Capability | What triggers it |
|---|---|
| `network` | `std::net`, `tokio::net`, `reqwest`, `hyper`, `ureq`, `curl`, `tungstenite` imports; URL and IP string literals |
| `file_read` | `std::fs`, `tokio::fs`, `walkdir`, `glob` imports |
| `file_write` | `std::fs::write`, `std::fs::remove_file`, `tempfile`, and other write-side fs functions |
| `process_exec` | `std::process`, `tokio::process`, `duct` imports |
| `env_access` | `std::env::var`, `std::env::vars`, `dotenvy`, `envy` imports |
| `unsafe_code` | `unsafe` blocks, `unsafe fn`, `unsafe impl` |
| `ffi` | `extern` blocks, `#[link]` attributes, `libc`, `nix`, `winapi`, `windows_sys` imports |
| `crypto` | `ring`, `rustls`, `openssl`, `aes`, `sha2`, `hmac`, `ed25519_dalek`, `x25519_dalek` imports; PEM blocks, hex-encoded keys, base58 private keys, key prefixes, credential prefixes in string literals |
| `system_time` | `std::time::SystemTime`, `std::time::Instant`, `chrono`, `time` imports |
| `proc_macro` | `#[proc_macro]`, `#[proc_macro_derive]`, `#[proc_macro_attribute]` attributes |

## Output

Each finding includes the capability type, source location, and evidence (the import path, attribute, or literal that triggered detection).

```json
{
  "findings": [
    {
      "capability": "network",
      "location": {
        "file": "src/client.rs",
        "line": 3,
        "column": 1
      },
      "evidence": "reqwest::Client"
    },
    {
      "capability": "unsafe_code",
      "location": {
        "file": "src/ffi.rs",
        "line": 10,
        "column": 5
      },
      "evidence": "unsafe block"
    }
  ]
}
```

## String Literal Analysis

Beyond import scanning, pedant inspects string literals for:

- **Hardcoded endpoints** — URLs (`http://`, `https://`, `ws://`, `wss://`), IPv4 addresses (e.g. `192.168.1.1:8080`), and IPv6 addresses (e.g. `[::1]:8080`). These produce `network` findings. Strings shorter than 8 characters are skipped.
- **PEM key material** — PEM-encoded keys and certificates (`-----BEGIN PRIVATE KEY-----`, `-----BEGIN CERTIFICATE-----`, etc.). These produce `crypto` findings.
- **Hex-encoded keys** — Pure hex strings at known private key sizes (64, 96, or 128+ chars). Covers Ed25519, X25519, AES-256, P-384, and combined keypair formats. These produce `crypto` findings.
- **Base58 private keys** — Bitcoin WIF keys (51-52 chars starting with 5/K/L) and Solana keypairs (64-88 base58 chars). These produce `crypto` findings.
- **Known key prefixes** — `AGE-SECRET-KEY-1` (age encryption), `xprv` (BIP32 extended private keys), `ed25519:` (NEAR protocol), `0x` + 64 hex chars (Ethereum-style private keys). These produce `crypto` findings.
- **Credential prefixes** — `AKIA` + 16 chars (AWS access key IDs), `ghp_`/`gho_`/`ghs_`/`ghr_` + 36 chars (GitHub tokens), `sk-`/`sk_live_`/`sk_test_` + 24+ chars (Stripe/OpenAI-style secrets). These produce `crypto` findings.

Evidence for key material longer than 40 characters is truncated (first 16 chars + `…` + last 4 chars) to avoid leaking full secrets in pedant's output.

## Gate Rules

Gate rules evaluate capability profiles for suspicious combinations. Run with `--gate`:

```bash
pedant --gate src/**/*.rs
```

9 built-in rules:

| Rule | Condition | Default Severity |
|------|-----------|-----------------|
| `build-script-network` | build_script + Network | deny |
| `build-script-exec` | build_script + ProcessExec | warn |
| `build-script-download-exec` | build_script + Network + ProcessExec | deny |
| `build-script-file-write` | build_script + FileWrite | warn |
| `proc-macro-network` | ProcMacro + Network | deny |
| `proc-macro-exec` | ProcMacro + ProcessExec | deny |
| `proc-macro-file-write` | ProcMacro + FileWrite | deny |
| `env-access-network` | EnvAccess + Network | info |
| `key-material-network` | Embedded key material + Network | warn |

Configure in `.pedant.toml`:

```toml
[gate]
# Disable a rule
build-script-exec = false

# Override severity
env-access-network = "warn"

# Disable all gate rules
enabled = false
```

Exit codes: `0` clean or warn-only, `1` deny-level verdict, `2` error.

## Attestation

Attestation wraps a capability profile with crate identity and a SHA-256 source hash for reproducibility:

```bash
pedant --attestation --crate-name my-crate --crate-version 0.1.0 src/**/*.rs

# From stdin
echo 'use std::net::TcpStream;' | pedant --stdin --attestation --crate-name test --crate-version 0.1.0
```

Output:

```json
{
  "spec_version": "0.1.0",
  "source_hash": "a1b2c3...",
  "crate_name": "my-crate",
  "crate_version": "0.1.0",
  "analysis_tier": "syntactic",
  "timestamp": 1741737600,
  "profile": {
    "findings": [...]
  }
}
```

The `analysis_tier` field is `"syntactic"` for default analysis or `"semantic"` when `--semantic` is used (type resolution via rust-analyzer). The source hash covers all analyzed file contents in deterministic (sorted path) order.

## Build Scripts

Build scripts (`build.rs` or custom paths from `Cargo.toml`'s `[package].build`) are automatically discovered and analyzed. Findings from build scripts carry `"build_script": true` in the JSON output, distinguishing compile-time capabilities from runtime capabilities. The `location.file` field identifies which file triggered each finding.

Build script discovery works by walking up from each source file to find a `Cargo.toml`, then checking for the build script path. Each crate root is only scanned once, even when multiple source files are passed.

## Diffing

Compare two capability profiles or attestations to see what changed:

```bash
# Diff two bare profiles
pedant --diff old_profile.json new_profile.json

# Diff two attestations (profiles are extracted automatically)
pedant --diff old_attestation.json new_attestation.json

# Mix formats — one attestation, one bare profile
pedant --diff attestation.json profile.json
```

Output:

```json
{
  "added": [
    {
      "capability": "file_read",
      "location": { "file": "src/lib.rs", "line": 1, "column": 0 },
      "evidence": "use std::fs::read"
    }
  ],
  "removed": [
    {
      "capability": "network",
      "location": { "file": "src/lib.rs", "line": 1, "column": 0 },
      "evidence": "use std::net::TcpStream"
    }
  ],
  "new_capabilities": ["file_read"],
  "dropped_capabilities": ["network"]
}
```

Exit codes: `0` no changes, `1` differences found, `2` error.

Format detection uses the `spec_version` key as a discriminant — files containing it are parsed as attestations, others as bare profiles.

## Semantic Analysis

With the `semantic` feature enabled (`cargo install pedant --features semantic`), pedant resolves types through aliases using rust-analyzer's analysis engine. This eliminates false positives where type aliases hide the real type:

- `type Handle = Arc<Inner>` — `clone()` on `Handle` is correctly identified as a cheap refcount bump
- `type MyMap = HashMap<K, V>` — default hasher check fires through the alias
- `use reqwest as http` — capability detection resolves the alias to its canonical path

```bash
pedant --semantic --capabilities src/**/*.rs
```

Requires a Cargo workspace. Falls back to syntactic analysis if the workspace can't be loaded.

## MCP Server

`pedant-mcp` exposes pedant's analysis as MCP tools for AI agents. Install and configure:

```bash
cargo install pedant-mcp

# User-scope (all projects):
claude mcp add --transport stdio --scope user pedant -- pedant-mcp

# Or project-scope (.mcp.json in project root):
echo '{"mcpServers":{"pedant":{"command":"pedant-mcp","args":[]}}}' > .mcp.json
```

Restart Claude Code after configuring. The server auto-discovers the Cargo workspace from CWD, indexes all crates, and watches for file changes.

Tools: `query_capabilities`, `query_gate_verdicts`, `query_violations`, `search_by_capability`, `explain_finding`, `audit_crate`.

For semantic analysis in the MCP server, set `PEDANT_SEMANTIC=1` before starting (requires the `semantic` feature to be compiled in).
