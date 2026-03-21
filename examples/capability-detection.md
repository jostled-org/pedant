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
| `crypto` | `ring`, `rustls`, `openssl`, `aes`, `sha2`, `hmac`, `ed25519_dalek`, `x25519_dalek` imports; PEM key material in string literals |
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

- **Hardcoded endpoints** — URLs (`http://`, `https://`, `ws://`, `wss://`), IPv4 addresses (e.g. `192.168.1.1:8080`), and IPv6 addresses (e.g. `[::1]:8080`). These produce `network` findings. Strings shorter than 8 characters are skipped to reduce false positives.
- **Key material** — PEM-encoded keys and certificates (`-----BEGIN PRIVATE KEY-----`, `-----BEGIN CERTIFICATE-----`, etc.). These produce `crypto` findings.

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

The source hash covers all analyzed file contents in deterministic (sorted path) order. Re-running against the same source produces the same hash.

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

## Design

Capability detection is syntactic (AST-only). It matches import paths and expressions against known prefixes. It does not resolve type aliases, follow trait implementations, or trace data flow across crate boundaries. For type-resolved analysis, see the planned `pedant-semantic` analyzer.
