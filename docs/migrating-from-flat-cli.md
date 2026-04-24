# Migrating From The Flat CLI

Pedant now uses subcommands instead of top-level mode flags.

Common migrations:

| Old | New |
|-----|-----|
| `pedant src/lib.rs` | `pedant check src/lib.rs` |
| `pedant --capabilities src/lib.rs` | `pedant capabilities src/lib.rs` |
| `pedant --attestation --crate-name foo --crate-version 0.1.0 src/lib.rs` | `pedant attestation --crate-name foo --crate-version 0.1.0 src/lib.rs` |
| `pedant --gate src/lib.rs` | `pedant gate src/lib.rs` |
| `pedant --diff old.json new.json` | `pedant diff old.json new.json` |
| `pedant --list-checks` | `pedant list-checks` |
| `pedant --explain max-depth` | `pedant explain max-depth` |

Semantic analysis stays command-local:

| Old | New |
|-----|-----|
| `pedant --semantic --gate src/lib.rs` | `pedant gate --semantic src/lib.rs` |
| `pedant --semantic --capabilities src/lib.rs` | `pedant capabilities --semantic src/lib.rs` |

Supply-chain baseline management is now built into the CLI:

| Workflow | Command |
|----------|---------|
| initialize baselines | `pedant supply-chain init --baseline-path .pedant/baselines` |
| refresh baselines after dep changes | `pedant supply-chain update --baseline-path .pedant/baselines` |
| verify committed baselines | `pedant supply-chain verify --baseline-path .pedant/baselines` |
