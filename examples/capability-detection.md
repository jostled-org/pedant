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

## Build Scripts

Capability detection applies to `build.rs` files the same as any other source file. The `location.file` field in findings identifies which file triggered each finding.

## Design

Capability detection is syntactic (AST-only). It matches import paths and expressions against known prefixes. It does not resolve type aliases, follow trait implementations, or trace data flow across crate boundaries. For type-resolved analysis, see the planned `pedant-semantic` analyzer.
