# Supply Chain Check

Pedant's supply chain check hashes every dependency's source on every build and compares against stored baselines. It catches three things:

- **Tag-swap attacks** — a version tag is moved to point at different code. The hash changes without a version bump.
- **Capability drift** — a dependency update adds new capabilities (e.g., a JSON parser suddenly gains `network` access).
- **New unaudited dependencies** — a dependency appears that has never been reviewed.

## How it works

1. Dependencies are vendored (`cargo vendor`, `npm ci`, `go mod vendor`, etc.)
2. Each dependency is scanned with `pedant --attestation`, producing a SHA-256 source hash and capability profile
3. The attestation is compared against a stored baseline in `.pedant/baselines/`
4. Hash mismatches, new capabilities, and missing baselines are reported

Pedant is built from the same pinned commit as the action — no registry fetch. One commit hash pins the action script, the scan logic, and the pedant binary. No second trust boundary.

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
      - uses: dtolnay/rust-toolchain@a54c7afe936fefeb4456b2dd8068152669aa8211 # stable
      - uses: Swatinem/rust-cache@9d47c6ad4b02e050fd481d890b2ea34778fd09d6 # v2.7.8
      - uses: jostled-org/pedant/.github/actions/supply-chain-check@<commit-hash>
        with:
          baseline-path: .pedant/baselines
          fail-on: hash-mismatch
          update-baselines: ${{ github.ref == 'refs/heads/main' && 'true' || 'false' }}
```

Replace `<commit-hash>` with a specific pedant commit. All action refs are pinned to commit hashes — no mutable tags.

### 2. Initialize baselines

The first run flags every dependency as `new-dependency`. To initialize:

```bash
# Run locally to generate baselines
cargo install --path /path/to/pedant/pedant --locked  # or cargo install pedant
BASELINE_PATH=".pedant/baselines" UPDATE_BASELINES=true ECOSYSTEMS=cargo \
  bash /path/to/pedant/.github/actions/supply-chain-check/scan.sh

# Commit the baselines
git add .pedant/baselines/
git commit -m "chore: initialize supply chain baselines"
```

Or let the first CI run on `main` generate them (with `update-baselines` set to true on main pushes).

### 3. Commit `.pedant/baselines/`

Baselines are committed to the repo. They're versioned alongside the lock file — when you approve a dependency change, the baseline updates on merge to main.

```
.pedant/baselines/
  cargo/
    serde/1.0.228.json
    tokio/1.44.2.json
    reqwest/0.12.18.json
  npm/
    axios/1.7.2.json
    express/4.21.0.json
```

Each file is a pedant attestation: `source_hash`, `crate_name`, `crate_version`, and capability `profile`.

## Workflow

### Normal build (no dep changes)

Pedant hashes each vendored dependency and compares against the baseline. Hashes match. Build passes. Fast — no capability scan needed for matching deps.

### Dependency update PR

```
=== Supply Chain Check: 2 finding(s) ===
::warning::[cargo] serde@1.0.229 — new capabilities: file_write
::notice::[cargo] new-dep@0.1.0 — capabilities: network, process_exec
```

The reviewer sees exactly what changed. They approve the PR if the new capabilities are expected, and baselines update on merge.

### Tag-swap attack

```
=== Supply Chain Check: 1 finding(s) ===
::error::[cargo] chrono@0.4.44 — content changed (baseline: 95efb4cfcd282828... current: deadbeefcd282828...)
```

Same version, different content. Build fails. No manual review needed — this is always wrong.

## Configuration

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `baseline-path` | `.pedant/baselines` | Where baselines are stored |
| `fail-on` | `hash-mismatch` | Fail threshold: `hash-mismatch`, `new-capability`, `new-dependency`, or `none` |
| `ecosystems` | auto-detected | Comma-separated: `cargo`, `npm`, `yarn`, `pnpm`, `go`, `pip` |
| `update-baselines` | `false` | Write new baselines after scan (use on main merges) |

### Fail-on levels

| Level | What it catches | When to use |
|-------|----------------|-------------|
| `hash-mismatch` | Tag-swap attacks only | Default — catches the worst attack with zero false positives |
| `new-capability` | Tag-swaps + capability drift | Stricter — flags dependency updates that add capabilities |
| `new-dependency` | All of the above + unreviewed deps | Strictest — every new dependency must be explicitly approved |
| `none` | Nothing (report only) | Monitoring mode — see findings without failing the build |

### Supported ecosystems

| Ecosystem | Lock file | Vendor method | Detection |
|-----------|-----------|--------------|-----------|
| Rust | `Cargo.lock` | `cargo vendor` | `.rs` files |
| npm | `package-lock.json` | `npm ci` | `.js`, `.mjs`, `.cjs`, `.ts` files |
| Yarn | `yarn.lock` | `yarn install --frozen-lockfile` | Same as npm |
| pnpm | `pnpm-lock.yaml` | `pnpm install --frozen-lockfile` | Same as npm |
| Go | `go.sum` | `go mod vendor` | `.go` files |
| Python | `poetry.lock` / `requirements.txt` | `pip download` + extract | `.py` files |

Ecosystems are auto-detected from lock files. Override with `ecosystems: "cargo,npm"`.

## Updating pedant

The action builds pedant from source at the pinned commit. To update:

```yaml
# Change one line:
- uses: jostled-org/pedant/.github/actions/supply-chain-check@old-hash
+ uses: jostled-org/pedant/.github/actions/supply-chain-check@new-hash
```

Review the commits between the two hashes before merging. Dependabot and Renovate can automate the PR.

## Requirements

- `bash`, `jq` (pre-installed on GitHub Actions runners)
- `cargo` (for Rust ecosystem and building pedant)
- Ecosystem-specific tools as needed (`npm`, `go`, `pip`, etc.)

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
