# Using pedant as a Claude Code Skill

This document describes an optional `/pedant` skill for Claude Code that runs a quick capability, gate, and style scan.

## Setup

Copy `pedant.md` to `~/.claude/commands/pedant.md` (or your project's `.claude/commands/` directory):

```markdown
Quick capability and gate rule scan on `$ARGUMENTS` (file paths, crate name, or empty for changed files).

## Steps

### 1. Determine scope

- If `$ARGUMENTS` is empty: use `git diff --name-only HEAD` to find changed `.rs` files
- If `$ARGUMENTS` is a crate name (matches a directory with `Cargo.toml`): find all `.rs` files under its `src/`
- Otherwise: treat `$ARGUMENTS` as file paths

If no `.rs` files found, print "no Rust files to scan" and stop.

### 2. Run capability scan

pedant --capabilities <files>

Print a summary: which capabilities were detected, with evidence.

### 3. Run gate rules

pedant --gate <files>

Print verdicts. Flag any deny-level results prominently.

### 4. Run style check

pedant <files>

Print violation count. If violations found, list them.

### 5. Summary

Print one-line verdict: clean, warnings only, or blocked (deny-level gate violations or style violations).
```

## Usage

```
/pedant                    # scan changed files
/pedant src/lib.rs         # scan a specific file
/pedant pedant-core        # scan all files in a crate
```

The skill is advisory — it reports findings but doesn't block. Use the [post-hook](pedant-claude-code-hook.md) for enforcement.
