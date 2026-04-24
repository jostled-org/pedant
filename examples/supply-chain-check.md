# Supply Chain Check

Pedant's supply chain check hashes every dependency's source on every build and compares against stored baselines. It catches three things:

- **Tag-swap attacks** — a version tag is moved to point at different code. The hash changes without a version bump.
- **Capability drift** — a dependency update adds new capabilities (e.g., a JSON parser suddenly gains `network` access).
- **New unaudited dependencies** — a dependency appears that has never been reviewed.

## How it works

1. Cargo dependencies are vendored with `cargo vendor`
2. Each dependency's Rust source files are scanned with `pedant supply-chain`, producing a SHA-256 source hash and capability profile
3. The attestation is compared against a stored baseline in `.pedant/baselines/`
4. Hash mismatches, new capabilities, and missing baselines are reported

Only Rust source files are hashed (`.rs`) — not metadata, not Cargo.toml rewrites, not checksum files. This makes hashes platform-independent: the same `.rs` files come from the same crate tarball regardless of OS or toolchain version.

## Trust model

The initial baseline trusts your current dependency tree. If a dependency is already compromised when you generate baselines, the compromised version becomes the baseline. The action detects *changes* from that point forward — not pre-existing compromises.

To audit from scratch, run `pedant capabilities` on each vendored dependency and review the capability profiles before committing baselines.

## Setup

### 1. Add the workflow

```yaml
# .github/workflows/supply-chain.yml
name: Supply Chain Check

on:
  push:
    branches: [main]
  pull_request:

jobs:
  supply-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8 # stable
      - uses: Swatinem/rust-cache@9d47c6ad4b02e050fd481d890b2ea34778fd09d6 # v2.7.8
      - uses: jostled-org/pedant/.github/actions/supply-chain-check@<commit-hash>
        with:
          baseline-path: .pedant/baselines
          fail-on: hash-mismatch
```

Replace `<commit-hash>` with a specific pedant commit. All action refs are pinned to commit hashes — no mutable tags.

### 2. Generate and commit baselines

```bash
# Install pedant
cargo install pedant

# Generate baselines
pedant supply-chain init --baseline-path .pedant/baselines

# Commit
git add .pedant/baselines/
git commit -m "chore: initialize supply chain baselines"
```

This is the trust anchor — you're accepting your current dependency tree as the known-good state.

### 3. Baselines in the repo

```
.pedant/baselines/
  cargo/
    serde/1.0.228.json
    tokio/1.44.2.json
    reqwest/0.12.18.json
```

Each file is a pedant attestation: source hash, package name, version, and capability profile.

## Workflow

### Normal build (no dep changes)

Pedant hashes each vendored dependency and compares against the baseline. Hashes match. Build passes.

### Dependency update

Update the dep, regenerate baselines for the changed packages, commit both the lock file and the updated baselines in the same PR:

```bash
cargo update -p serde
pedant supply-chain update --baseline-path .pedant/baselines
git add Cargo.lock .pedant/baselines/
git commit -m "chore: update serde and baselines"
```

`update` keeps the current dependency tree authoritative: stale version files and baseline directories for removed crates are pruned automatically.

CI verifies the baselines match the vendored source. The reviewer sees both the dep change and the capability diff.

### Tag-swap attack

```
=== Supply Chain Check: 1 finding(s) ===
::error::[cargo] chrono@0.4.44 — content changed (baseline: 95efb4cf... current: deadbeef...)
```

Same version, different content. Build fails. No baseline update fixes this — the content genuinely changed.

## Configuration

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `baseline-path` | `.pedant/baselines` | Where baselines are stored |
| `fail-on` | `hash-mismatch` | Fail threshold: `hash-mismatch`, `new-capability`, `new-dependency`, or `none` |
| `debug-package` | unset | Print the exact hashed Rust inputs for one vendored crate during `pedant supply-chain verify` |

### Fail-on levels

| Level | What it catches | When to use |
|-------|----------------|-------------|
| `hash-mismatch` | Tag-swap attacks only | Default — catches the worst attack with zero false positives |
| `new-capability` | Tag-swaps + capability drift | Stricter — flags dependency updates that add capabilities |
| `new-dependency` | All of the above + unreviewed deps | Strictest — every new dependency must be explicitly approved |
| `none` | Nothing (report only) | Monitoring mode — see findings without failing the build |

### Supported ecosystems

Current implementation: Cargo only.

| Ecosystem | Lock file | Vendor method | Scanned files |
|-----------|-----------|--------------|---------------|
| Rust | `Cargo.lock` | `cargo vendor` | `.rs` |

## Updating pedant

The action builds pedant from source at the pinned commit. To update:

```yaml
# Change one line:
- uses: jostled-org/pedant/.github/actions/supply-chain-check@old-hash
+ uses: jostled-org/pedant/.github/actions/supply-chain-check@new-hash
```

Review the commits between the two hashes before merging. Dependabot and Renovate can automate the PR.

## Requirements

- `cargo` (for vendoring Rust dependencies and building pedant)

## Outputs

| Output | Description |
|--------|-------------|
| `status` | `clean`, `new-dependency`, `new-capability`, or `hash-mismatch` |
| `report` | Path to a JSON file with all findings |

Use outputs in subsequent steps:

```yaml
- uses: jostled-org/pedant/.github/actions/supply-chain-check@<commit>
  id: supply-chain
- run: echo "Status: ${{ steps.supply-chain.outputs.status }}"
```

## Debugging mismatches

When a crate fails verification and you need to compare local and CI inputs, run:

```bash
pedant supply-chain verify --baseline-path .pedant/baselines --debug-package cc
```

This prints the crate version, aggregate `source_hash`, and one line per hashed Rust file with its relative path, byte length, and per-file SHA-256 digest.
