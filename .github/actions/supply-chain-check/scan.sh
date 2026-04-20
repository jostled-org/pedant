#!/usr/bin/env bash
#
# Supply chain capability check.
#
# Vendors dependencies, runs pedant attestations, compares against stored
# baselines. Detects: tag-swap attacks (hash mismatch on same version),
# capability drift (new capabilities in updated deps), and new unaudited
# dependencies.
#
# Requirements: bash, jq, pedant (built by action.yml from source)
#
# Environment:
#   BASELINE_PATH    — directory for stored attestation baselines
#   FAIL_ON          — threshold: hash-mismatch | new-capability | new-dependency | none
#   ECOSYSTEMS       — comma-separated list, or empty for auto-detect
#   UPDATE_BASELINES — "true" to write baselines after scan

set -euo pipefail

BASELINE_PATH="${BASELINE_PATH:-.pedant/baselines}"
FAIL_ON="${FAIL_ON:-hash-mismatch}"
ECOSYSTEMS="${ECOSYSTEMS:-}"
UPDATE_BASELINES="${UPDATE_BASELINES:-false}"

VENDOR_DIR="$(mktemp -d)"
FINDINGS_FILE="$(mktemp)"
REPORT_FILE="$(mktemp)"
: > "$FINDINGS_FILE"

# ── Severity ──────────────────────────────────────────────────────────

severity_rank() {
  case "$1" in
    hash-mismatch)    echo 3 ;;
    new-capability)   echo 2 ;;
    new-dependency)   echo 1 ;;
    *)                echo 0 ;;
  esac
}

FAIL_RANK=$(severity_rank "$FAIL_ON")

finding() {
  echo "${1}|${2}|${3}|${4}|${5}" >> "$FINDINGS_FILE"
}

# ── Ecosystem detection ───────────────────────────────────────────────

detect_ecosystems() {
  local found=()
  [ -f Cargo.lock ]        && found+=(cargo)
  [ -f package-lock.json ] && found+=(npm)
  [ -f yarn.lock ]         && found+=(yarn)
  [ -f pnpm-lock.yaml ]   && found+=(pnpm)
  [ -f go.sum ]            && found+=(go)
  [ -f poetry.lock ]       && found+=(pip)
  [ -f requirements.txt ]  && found+=(pip)
  echo "${found[*]}"
}

if [ -n "$ECOSYSTEMS" ]; then
  IFS=',' read -ra ACTIVE_ECOSYSTEMS <<< "$ECOSYSTEMS"
else
  IFS=' ' read -ra ACTIVE_ECOSYSTEMS <<< "$(detect_ecosystems)"
fi

if [ ${#ACTIVE_ECOSYSTEMS[@]} -eq 0 ]; then
  echo "::notice::No supported lock files found. Nothing to scan."
  echo "status=clean" >> "${GITHUB_OUTPUT:-/dev/null}"
  exit 0
fi

echo "Detected ecosystems: ${ACTIVE_ECOSYSTEMS[*]}"

# ── Vendoring ─────────────────────────────────────────────────────────

vendor_cargo() {
  cargo vendor "$VENDOR_DIR/cargo" --quiet 2>/dev/null
  echo "$VENDOR_DIR/cargo"
}

vendor_npm() {
  npm ci --ignore-scripts --quiet 2>/dev/null
  echo "node_modules"
}

vendor_yarn() {
  yarn install --frozen-lockfile --ignore-scripts --silent 2>/dev/null
  echo "node_modules"
}

vendor_pnpm() {
  pnpm install --frozen-lockfile --ignore-scripts --silent 2>/dev/null
  echo "node_modules"
}

vendor_go() {
  go mod vendor 2>/dev/null
  echo "vendor"
}

vendor_pip() {
  local dest="$VENDOR_DIR/pip"
  mkdir -p "$dest"
  if [ -f poetry.lock ]; then
    poetry export -f requirements.txt --without-hashes -o "$dest/.requirements.txt" 2>/dev/null
    pip download --no-binary :all: -d "$dest/sdists" -r "$dest/.requirements.txt" 2>/dev/null
  elif [ -f requirements.txt ]; then
    pip download --no-binary :all: -d "$dest/sdists" -r requirements.txt 2>/dev/null
  fi
  for archive in "$dest/sdists"/*.tar.gz; do
    [ -f "$archive" ] || continue
    tar xzf "$archive" -C "$dest" 2>/dev/null
  done
  for archive in "$dest/sdists"/*.zip; do
    [ -f "$archive" ] || continue
    unzip -qo "$archive" -d "$dest" 2>/dev/null
  done
  echo "$dest"
}

# ── Per-ecosystem dependency enumeration ──────────────────────────────
#
# Each function outputs lines of: name version source_dir extensions
# Extensions are comma-separated (e.g. "rs" or "js,mjs,cjs,ts").

enumerate_cargo() {
  local vendor_path="$1"
  for dep_dir in "$vendor_path"/*/; do
    [ -d "$dep_dir" ] || continue
    local dirname
    dirname=$(basename "$dep_dir")
    local name version
    name=$(sed -n 's/^name = "\(.*\)"/\1/p' "$dep_dir/Cargo.toml" 2>/dev/null | head -1)
    version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$dep_dir/Cargo.toml" 2>/dev/null | head -1)
    [ -z "$name" ] && name="$dirname"
    [ -z "$version" ] && version="unknown"
    echo "$name $version $dep_dir rs"
  done
}

enumerate_npm() {
  local vendor_path="$1"
  for dep_dir in "$vendor_path"/*/; do
    [ -d "$dep_dir" ] || continue
    local dirname
    dirname=$(basename "$dep_dir")
    case "$dirname" in
      .*) continue ;;
      @*)
        for scoped_dir in "$dep_dir"/*/; do
          [ -d "$scoped_dir" ] || continue
          local scoped_name
          scoped_name=$(basename "$scoped_dir")
          local name="$dirname/$scoped_name"
          local version
          version=$(jq -r '.version // "unknown"' "$scoped_dir/package.json" 2>/dev/null || echo "unknown")
          echo "$name $version $scoped_dir js,mjs,cjs,ts"
        done
        continue
        ;;
    esac
    local version
    version=$(jq -r '.version // "unknown"' "$dep_dir/package.json" 2>/dev/null || echo "unknown")
    echo "$dirname $version $dep_dir js,mjs,cjs,ts"
  done
}

enumerate_go() {
  local vendor_path="$1"
  find "$vendor_path" -name '*.go' -not -path '*/testdata/*' -exec dirname {} \; | \
    sort -u | while read -r mod_dir; do
      local mod_path="${mod_dir#vendor/}"
      echo "$mod_path unknown $mod_dir go"
    done
}

enumerate_pip() {
  local vendor_path="$1"
  for dep_dir in "$vendor_path"/*/; do
    [ -d "$dep_dir" ] || continue
    local dirname
    dirname=$(basename "$dep_dir")
    case "$dirname" in
      sdists|.*) continue ;;
    esac
    local name version
    if [[ "$dirname" =~ ^(.+)-([0-9]+\..+)$ ]]; then
      name="${BASH_REMATCH[1]}"
      version="${BASH_REMATCH[2]}"
    else
      name="$dirname"
      version="unknown"
    fi
    echo "$name $version $dep_dir py"
  done
}

# ── Scanning ──────────────────────────────────────────────────────────

scan_dependency() {
  local ecosystem="$1" name="$2" version="$3" source_dir="$4" extensions="$5"
  local safe_name
  safe_name=$(echo "$name" | tr '/' '_')
  local baseline_file="$BASELINE_PATH/$ecosystem/${safe_name}/${version}.json"
  local attestation_file
  attestation_file="$(mktemp)"

  # Collect source files by extension, sorted for deterministic hashing.
  # Use paths relative to source_dir so hashes are stable across vendor locations.
  local files=()
  IFS=',' read -ra exts <<< "$extensions"
  for ext in "${exts[@]}"; do
    while IFS= read -r f; do
      files+=("$f")
    done < <(cd "$source_dir" && find . -name "*.${ext}" -type f 2>/dev/null | sort) || true
  done

  if [ ${#files[@]} -eq 0 ]; then
    rm -f "$attestation_file"
    return 0
  fi

  # Run pedant from the source dir so relative paths are stable.
  # Violations go to stderr; clean JSON on stdout.
  (cd "$source_dir" && pedant --attestation \
    --crate-name "$name" --crate-version "$version" \
    "${files[@]}") > "$attestation_file" 2>/dev/null || true

  # Verify valid JSON with a source_hash field.
  if ! jq -e '.source_hash' "$attestation_file" > /dev/null 2>&1; then
    rm -f "$attestation_file"
    return 0
  fi

  local current_hash
  current_hash=$(jq -r '.source_hash' "$attestation_file")

  local baseline_dir="$BASELINE_PATH/$ecosystem/${safe_name}"

  if [ -f "$baseline_file" ]; then
    # Exact version baseline exists — check for hash mismatch (tag-swap).
    local baseline_hash
    baseline_hash=$(jq -r '.source_hash' "$baseline_file")

    if [ "$current_hash" != "$baseline_hash" ]; then
      finding "hash-mismatch" "$ecosystem" "$name" "$version" \
        "content changed (baseline: ${baseline_hash:0:16}... current: ${current_hash:0:16}...)"
    fi
  else
    # No exact version baseline. Check for a prior version to diff against.
    local prior_baseline=""
    if [ -d "$baseline_dir" ]; then
      prior_baseline=$(ls -t "$baseline_dir"/*.json 2>/dev/null | head -1)
    fi

    if [ -n "$prior_baseline" ]; then
      # Version upgrade — diff capabilities against the prior version.
      local prior_version
      prior_version=$(basename "$prior_baseline" .json)
      local diff_output
      diff_output=$(pedant --diff "$prior_baseline" "$attestation_file" 2>/dev/null || true)
      local added=""
      if [ -n "$diff_output" ]; then
        added=$(echo "$diff_output" | jq -r '.new_capabilities | if length > 0 then join(", ") else empty end' 2>/dev/null || echo "")
      fi
      if [ -n "$added" ]; then
        finding "new-capability" "$ecosystem" "$name" "$version" \
          "upgraded from $prior_version — new capabilities: $added"
      fi
    else
      # Genuinely new dependency — no prior baseline at all.
      local caps
      caps=$(jq -r '[.profile.findings[].capability] | unique | join(", ") // "none"' "$attestation_file")
      [ -z "$caps" ] && caps="none"
      finding "new-dependency" "$ecosystem" "$name" "$version" "capabilities: $caps"
    fi
  fi

  if [ "$UPDATE_BASELINES" = "true" ]; then
    mkdir -p "$baseline_dir"
    cp "$attestation_file" "$baseline_file"
  fi

  rm -f "$attestation_file"
}

# ── Main loop ─────────────────────────────────────────────────────────

for ecosystem in "${ACTIVE_ECOSYSTEMS[@]}"; do
  echo "::group::Scanning $ecosystem dependencies"

  vendor_path=""
  case "$ecosystem" in
    cargo) vendor_path=$(vendor_cargo) ;;
    npm)   vendor_path=$(vendor_npm)   ;;
    yarn)  vendor_path=$(vendor_yarn)  ;;
    pnpm)  vendor_path=$(vendor_pnpm)  ;;
    go)    vendor_path=$(vendor_go)    ;;
    pip)   vendor_path=$(vendor_pip)   ;;
    *)
      echo "::warning::Unknown ecosystem: $ecosystem"
      continue
      ;;
  esac

  if [ -z "$vendor_path" ] || [ ! -d "$vendor_path" ]; then
    echo "::warning::Vendoring failed for $ecosystem"
    echo "::endgroup::"
    continue
  fi

  dep_list="$(mktemp)"
  case "$ecosystem" in
    cargo)         enumerate_cargo "$vendor_path" > "$dep_list" ;;
    npm|yarn|pnpm) enumerate_npm "$vendor_path" > "$dep_list" ;;
    go)            enumerate_go "$vendor_path" > "$dep_list" ;;
    pip)           enumerate_pip "$vendor_path" > "$dep_list" ;;
  esac

  while read -r name version source_dir extensions; do
    [ -z "$name" ] && continue
    echo "  Scanning $name@$version"
    scan_dependency "$ecosystem" "$name" "$version" "$source_dir" "$extensions"
  done < "$dep_list"
  rm -f "$dep_list"

  echo "::endgroup::"
done

# ── Report ────────────────────────────────────────────────────────────

total=$(wc -l < "$FINDINGS_FILE" | tr -d ' ')

# Build JSON report.
{
  echo '{"findings": ['
  first=true
  while IFS='|' read -r level ecosystem name version detail; do
    [ -z "$level" ] && continue
    if [ "$first" = true ]; then
      first=false
    else
      echo ","
    fi
    printf '  {"level": "%s", "ecosystem": "%s", "name": "%s", "version": "%s", "detail": "%s"}' \
      "$level" "$ecosystem" "$name" "$version" "$detail"
  done < "$FINDINGS_FILE"
  echo ""
  echo "]}"
} > "$REPORT_FILE"

if [ "$total" -eq 0 ]; then
  echo ""
  echo "All dependencies match baselines."
  echo "status=clean" >> "${GITHUB_OUTPUT:-/dev/null}"
else
  echo ""
  echo "=== Supply Chain Check: $total finding(s) ==="
  worst="clean"
  while IFS='|' read -r level ecosystem name version detail; do
    [ -z "$level" ] && continue
    case "$level" in
      hash-mismatch)  echo "::error::[$ecosystem] $name@$version — $detail" ;;
      new-capability) echo "::warning::[$ecosystem] $name@$version — $detail" ;;
      new-dependency) echo "::notice::[$ecosystem] $name@$version — $detail" ;;
    esac
    case "$level" in
      hash-mismatch)  worst="hash-mismatch" ;;
      new-capability) [ "$worst" != "hash-mismatch" ] && worst="new-capability" ;;
      new-dependency) [ "$worst" = "clean" ] && worst="new-dependency" ;;
    esac
  done < "$FINDINGS_FILE"
  echo "status=$worst" >> "${GITHUB_OUTPUT:-/dev/null}"
fi

echo "report=$REPORT_FILE" >> "${GITHUB_OUTPUT:-/dev/null}"

# Determine exit code.
EXIT_CODE=0
if [ "$FAIL_RANK" -gt 0 ]; then
  while IFS='|' read -r level _ _ _ _; do
    [ -z "$level" ] && continue
    rank=$(severity_rank "$level")
    if [ "$rank" -ge "$FAIL_RANK" ]; then
      EXIT_CODE=1
      break
    fi
  done < "$FINDINGS_FILE"
fi

rm -rf "$VENDOR_DIR"
rm -f "$FINDINGS_FILE"

exit $EXIT_CODE
