#!/usr/bin/env bash
#
# Permit publication only when tagged package source still matches that tag.
#
# release-plz writes version changes in its release PR. An implementation commit
# can contain new APIs while retaining the last published version locally. Cargo
# path resolution hides that mismatch, but packaging replaces the path with the
# older registry crate. Exit 1 tells the workflow to wait for the release PR;
# other non-zero statuses report an infrastructure or repository error.

set -euo pipefail

for tool in cargo git jq; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "error: ${tool} is required on PATH." >&2
        exit 2
    fi
done

repo_root="$(git rev-parse --show-toplevel)"
cd "${repo_root}"

metadata="$(cargo metadata --no-deps --format-version 1)"
packages="$({
    jq -er '
        [.packages[]
         | select(.publish == null or (.publish | length) > 0)
         | [.name, .version, .manifest_path]
         | @tsv]
        | if length > 0 then .[] else error("no publishable packages") end
    ' <<<"${metadata}"
})"
status=0

while IFS=$'\t' read -r package version manifest_path; do
    tag="${package}-v${version}"
    tag_status=0
    git show-ref --verify --quiet "refs/tags/${tag}" || tag_status=$?
    case "${tag_status}" in
        0) ;;
        1) continue ;;
        *)
            echo "error: git could not inspect release tag ${tag}." >&2
            exit 2
            ;;
    esac

    package_directory="$(dirname -- "${manifest_path}")"
    relative_directory="${package_directory#"${repo_root}/"}"
    diff_status=0
    git diff --quiet "${tag}" HEAD -- "${relative_directory}" || diff_status=$?
    case "${diff_status}" in
        0) ;;
        1)
            echo "release deferred: ${package} source changed after ${tag}; waiting for the release PR version." >&2
            status=1
            ;;
        *)
            echo "error: git could not compare ${package} with ${tag}." >&2
            exit 2
            ;;
    esac
done <<<"${packages}"

case "${status}" in
    0) echo "release readiness check: ready" ;;
    1) exit 1 ;;
esac
