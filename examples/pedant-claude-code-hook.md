# Using pedant with Claude Code Hooks

This document describes how to configure a Claude Code PostToolUse hook that runs pedant after Edit/Write operations on Rust files.

## Overview

The hook:
- Runs pedant on .rs files after Edit/Write operations
- Blocks edits that introduce coding standard violations
- Shows violation details inline in Claude's tool results

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

# Skip test files (optional)
[[ "$file_path" == */tests/* ]] && exit 0

# Skip if file doesn't exist
[ -f "$file_path" ] || exit 0

# Run pedant (capture exit code without triggering set -e)
output=$(pedant -f json "$file_path" 2>&1) && exit_code=0 || exit_code=$?

if [ $exit_code -eq 1 ]; then
    violations=$(echo "$output" | jq -r '.[] | "  L\(.line): \(.check) - \(.message)"' 2>/dev/null || echo "$output")
    echo "PEDANT VIOLATIONS - FIX BEFORE PROCEEDING" >&2
    echo "File: $file_path" >&2
    echo "$violations" >&2
    exit 2
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
3. For .rs files, pedant runs and checks for violations
4. If violations found (exit code 1):
   - Violations are written to stderr
   - Hook exits with code 2 (blocking error)
   - Claude sees the violations inline and must fix them
5. If no violations (exit code 0): edit proceeds normally

## Key Implementation Detail

The line:
```bash
output=$(pedant -f json "$file_path" 2>&1) && exit_code=0 || exit_code=$?
```

This pattern captures pedant's exit code without triggering `set -e`. A naive approach:
```bash
output=$(pedant -f json "$file_path" 2>&1)
exit_code=$?  # Never reached if pedant returns non-zero
```

With `set -e`, the script exits immediately when pedant returns 1, before capturing the exit code or outputting violations.

## Example Output

When Claude introduces a nested match violation:

```
PostToolUse:Edit hook blocking error from command: "~/.claude/hooks/pedant-check.sh":
PEDANT VIOLATIONS - FIX BEFORE PROCEEDING
File: /path/to/file.rs
  L42: nesting - nested match expression, consider tuple matching
```

Claude then sees this inline and fixes the violation before proceeding.
