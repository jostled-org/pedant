#!/usr/bin/env bash

set -euo pipefail

FORMAT_ROOT="$(git rev-parse --show-toplevel)"
readonly FORMAT_ROOT
cd "$FORMAT_ROOT"

list_sources() {
    git ls-files -z -- '*.rs' |
        while IFS= read -r -d '' source; do
            case "$source" in
                */tests/fixtures/*) continue ;;
                *) printf '%s\0' "$source" ;;
            esac
        done
}

case "${1:-}" in
    --list)
        list_sources | tr '\0' '\n'
        ;;
    '')
        FORMAT_LISTING="$(mktemp)"
        readonly FORMAT_LISTING
        trap 'rm -f "$FORMAT_LISTING"' EXIT
        list_sources > "$FORMAT_LISTING"
        if [[ ! -s "$FORMAT_LISTING" ]]; then
            echo "error: the repository holds no format-owned Rust source" >&2
            exit 1
        fi
        xargs -0 rustfmt --edition 2024 --check -- < "$FORMAT_LISTING"
        ;;
    *)
        echo "usage: $0 [--list]" >&2
        exit 2
        ;;
esac
