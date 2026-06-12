# Using pedant with Claude Code Hooks

This document describes how to configure a Claude Code PostToolUse hook that runs pedant after Edit/Write operations on Rust files.

## Overview

The hook:
- Runs pedant style checks on .rs files after Edit/Write operations
- Runs gate rules against the file's capability profile
- Blocks edits that introduce coding standard violations or deny-level gate verdicts
- Shows violation details inline in Claude's tool results
- Reports loudly (without blocking) if the pedant CLI itself fails, so a broken
  install never silently disables enforcement

## Configuration

### 1. Claude Code Settings

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/hooks/pedant-check.sh"
          }
        ]
      }
    ]
  }
}
```

### 2. Hook Script

Create `~/.claude/hooks/pedant-check.sh`:

```bash
#!/bin/bash
# pedant hook - validates Rust code after Edit/Write operations
set -euo pipefail

input=$(cat)
tool_name=$(echo "$input" | jq -r '.tool_name')
file_path=$(echo "$input" | jq -r '.tool_input.file_path // empty')

# Only process .rs files
[[ "$file_path" == *.rs ]] || exit 0

# Skip test and bench files
[[ "$file_path" == */tests/* ]] && exit 0
[[ "$file_path" == */benches/* ]] && exit 0

# Skip if file doesn't exist
[ -f "$file_path" ] || exit 0

# Find nearest pedant.toml by walking up from the file's directory
find_pedant_config() {
    local dir="$1"
    while [ "$dir" != "/" ]; do
        if [ -f "$dir/.pedant.toml" ]; then
            echo "$dir/.pedant.toml"
            return
        fi
        dir=$(dirname "$dir")
    done
    # Fall back to global config
    local global="${XDG_CONFIG_HOME:-$HOME/.config}/pedant/config.toml"
    [ -f "$global" ] && echo "$global"
}

config=$(find_pedant_config "$(dirname "$file_path")") || config=""
check_args=(check -f json)
[ -n "$config" ] && check_args+=(-c "$config")

# Run pedant style checks (capture exit code without triggering set -e)
output=$(pedant "${check_args[@]}" "$file_path" 2>&1) && exit_code=0 || exit_code=$?

if [ $exit_code -eq 1 ]; then
    violations=$(echo "$output" | jq -r '.violations[] | "  L\(.line): \(.check) - \(.message)"' 2>/dev/null || echo "$output")
    echo "PEDANT VIOLATIONS - FIX BEFORE PROCEEDING" >&2
    echo "File: $file_path" >&2
    echo "$violations" >&2
    exit 2
fi

if [ $exit_code -ge 2 ]; then
    # CLI or config breakage must be visible, not silently skipped — but a
    # broken pedant must not block edits.
    echo "PEDANT HOOK: pedant check failed (exit ${exit_code}) — style checks were NOT run" >&2
    echo "$output" >&2
    exit 0
fi

# Run gate rules on capability profile (only blocks on deny-level verdicts)
gate_output=$(pedant gate "$file_path" 2>&1) && gate_code=0 || gate_code=$?

if [ $gate_code -eq 1 ]; then
    echo "PEDANT GATE RULE VIOLATION" >&2
    echo "File: $file_path" >&2
    echo "$gate_output" >&2
    exit 2
fi

if [ $gate_code -ge 2 ]; then
    echo "PEDANT HOOK: pedant gate failed (exit ${gate_code}) — gate rules were NOT run" >&2
    echo "$gate_output" >&2
    exit 0
fi

exit 0
```

Make it executable:
```bash
chmod +x ~/.claude/hooks/pedant-check.sh
```

## How It Works

1. Claude Code calls the hook after every Edit/Write operation
2. Hook receives JSON input with `tool_name` and `tool_input.file_path`
3. For .rs files, `pedant check -f json` runs first:
   - Exit 0 (clean): continue to gate rules
   - Exit 1 (violations): violations are written to stderr, hook exits 2
     (blocking error), Claude sees them inline and must fix them
   - Exit ≥ 2 (CLI/config failure): a loud warning is written to stderr but
     the hook exits 0 — pedant being broken must be visible without blocking
     every edit
4. `pedant gate` then evaluates gate rules on the file's capability profile
   with the same exit-code mapping — deny-level verdicts block, gate failures
   warn

## Key Implementation Details

### Exit-code capture under `set -e`

```bash
output=$(pedant "${check_args[@]}" "$file_path" 2>&1) && exit_code=0 || exit_code=$?
```

This pattern captures pedant's exit code without triggering `set -e`. A naive
`output=$(...)` followed by `exit_code=$?` never reaches the second line when
pedant returns non-zero.

### JSON output shape

`pedant check -f json` emits a single object, not a bare array:

```json
{
  "analysis_tier": "syntactic",
  "had_error": false,
  "violations": [
    { "check": "nested-if", "line": 3, "message": "if nested inside if, ..." }
  ]
}
```

The hook reads `.violations[]`. (The pre-subcommand CLI emitted a top-level
array — see `docs/migrating-from-flat-cli.md` if you have an old copy of this
hook checking `.[]`.)

### Visible failure over silent rot

The exit ≥ 2 branches exist because of a real failure mode: after the CLI
moved to subcommands, old hooks calling `pedant -f json` received a usage
error (exit 2), matched neither the violation branch nor the success branch,
and silently passed every file. Enforcement was off for weeks and nothing
said so. A hook that cannot run its checker must say so loudly.

## Example Output

When Claude introduces a nested match violation:

```
PostToolUse:Edit hook blocking error from command: "~/.claude/hooks/pedant-check.sh":
PEDANT VIOLATIONS - FIX BEFORE PROCEEDING
File: /path/to/file.rs
  L42: nested-match - nested match expression, consider tuple matching
```

Claude then sees this inline and fixes the violation before proceeding.
