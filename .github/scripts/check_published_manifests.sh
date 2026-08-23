#!/usr/bin/env bash
#
# Reject changes to a package manifest after that exact version was tagged.
#
# Cargo replaces path dependencies with registry dependencies while packaging.
# A workspace build therefore hides an immutable-version mistake: local crates
# all see the edited path manifest, while `cargo publish` sees the manifest that
# crates.io recorded for that version. If a first-party dependency changes but
# the package version does not, those two graphs can contain different versions
# of a shared type crate and fail only during tarball verification.
#
# release-plz tags workspace packages as `<package>-v<version>`. A package with
# no tag for its current version is awaiting release and may have any manifest
# change. Once the exact tag exists, Cargo.toml is immutable; any later edit
# requires a new package version.
#
# Exit 0 clean, exit 1 on violation.

set -euo pipefail

# `CDPATH` is cleared inside the substitution: `dirname` yields a bare relative
# path for a script invoked by a relative path, `cd` then consults `CDPATH`, and
# a match there both enters the wrong directory and prints it — leaving
# `script_dir` a two-line value naming a tree this repository does not own.
script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=repository_check_lib.sh
. "${script_dir}/repository_check_lib.sh"

cd_repo_root

# `rg` joins the list because `workspace_metadata` now classifies cargo's own
# output: without it, an unavailable registry would be reported as manifest
# drift rather than as a machine to retry on.
require_tools cargo git jq rg

metadata="$(workspace_metadata)"
repo_root="$(pwd)"
status=0
packages="$(
    jq -er '
        [.packages[]
         | select(.publish == null or (.publish | length) > 0)
         | [.name, .version, .manifest_path]
         | @tsv]
        | if length > 0 then .[] else error("no publishable packages") end
    ' <<<"${metadata}"
)"

while IFS=$'\t' read -r package version manifest_path; do
    tag="${package}-v${version}"
    relative_manifest="${manifest_path#"${repo_root}/"}"
    tag_status=0

    git show-ref --verify --quiet "refs/tags/${tag}" || tag_status=$?
    case "${tag_status}" in
        0) ;;
        1) continue ;;
        *)
            echo "error: git could not inspect release tag ${tag}." >&2
            exit 1
            ;;
    esac

    diff_status=0
    git diff --quiet "${tag}" -- "${relative_manifest}" || diff_status=$?
    case "${diff_status}" in
        0) ;;
        1)
            echo "error: ${relative_manifest} changed after ${tag} was created." >&2
            echo "Bump ${package} to a new version before publishing dependents." >&2
            status=1
            ;;
        *)
            echo "error: git could not compare ${relative_manifest} with ${tag}." >&2
            exit 1
            ;;
    esac
done <<<"${packages}"

if [ "${status}" -ne 0 ]; then
    echo "error: published package manifest drift detected." >&2
    exit 1
fi

echo "published package manifest check: clean"
