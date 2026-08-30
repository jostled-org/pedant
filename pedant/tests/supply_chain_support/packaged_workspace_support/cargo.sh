#!/bin/sh
# The stand-in Cargo one packaged-workspace lifecycle row installs on PATH.
#
# It implements the whole operation protocol the tracked proof drives, records
# the target root every call inherited and the process ids it owns, and injects
# at most one fault. A fault is an operation that fails, or an archive graph
# bent into a shape the proof has to refuse. It compiles nothing: a row proves
# the proof's lifecycle, not Cargo's.

set -eu

state="${FAKE_STATE_DIR}"
printf '%s\n' "$$" >> "${state}/pids"
printf '%s\n' "${CARGO_TARGET_DIR:-}" >> "${state}/targets"

# One failure convention, shared with the other fake this proof installs: name
# the fake, state what it was asked, and leave with 2. A fake that answered 0 to
# a request it did not recognize would make every row that reached it vacuous,
# and two fakes each inventing a refusal are two shapes a row has to know.
refuse() {
    printf 'error: the fake cargo %s\n' "$1" >&2
    exit 2
}

# Declared above the scan, because an empty argument list is a request this fake
# has to refuse in its own words rather than one `set -u` reports on its behalf.
[ "$#" -gt 0 ] || refuse "was given no operation"

operation="$1"
shift

manifest=""
install_root=""
package_path=""
last_argument=""
no_deps=0
previous=""
for argument in "$@"; do
    case "${previous}" in
        --manifest-path) manifest="${argument}" ;;
        --root) install_root="${argument}" ;;
        --path) package_path="${argument}" ;;
    esac
    case "${argument}" in
        --no-deps) no_deps=1 ;;
    esac
    last_argument="${argument}"
    previous="${argument}"
done

log() {
    printf '%s\n' "$1" >> "${state}/operations"
}

# One flag the selected operation consumes, present in the scan above.
#
# The scan recognizes the space form the proof writes and nothing else. An
# operation that ran without what it needs would write outside this row's roots
# — `install` would create `/bin` and copy into it, `generate-lockfile` would
# drop a `Cargo.lock` in whatever directory this child started in — and still
# report success.
require() {
    if [ -z "$2" ]; then
        refuse "needs $1 for ${operation}"
    fi
}

# Every producer below writes to a file and every reader is given that file.
# `#!/bin/sh` has no `pipefail`, so a pipeline reports the reader's status alone:
# a producer that failed on a member manifest it could not read would emit
# nothing, `jq` would turn the empty stream into a well-formed document, and this
# fake would answer 0 with a graph the proof then judges as real.
#
# One manifest as `cargo metadata` describes it, with its first-party edges.
#
# An edge is read in both spellings a manifest may carry it in: the bare
# requirement an unconditional edge uses, and the table an optional one needs to
# hold `optional = true`. Cargo reports both the same way, and a reader that saw
# only the first would drop the gated edge from the metadata every patch, member
# and requirement check downstream is judged against — leaving the proof
# reporting a green graph for an edge it never looked at.
package_json() {
    package_manifest="$1"
    package_directory=$(dirname "${package_manifest}")
    package_name=$(rg -N -o -r '${1}' '^name = "([^"]+)"$' "${package_manifest}")
    package_version=$(rg -N -o -r '${1}' '^version = "([^"]+)"$' "${package_manifest}")
    # The scan's own status is read, not just its failure. Ripgrep answers 1 for
    # a manifest that declares no first-party edge, which is an empty edge list
    # and a graph this fake may still describe. Every other status — an
    # unreadable manifest, a pattern it refused, a ripgrep that is not installed
    # — means the manifest was never searched, and an empty edge list from a
    # search that never ran produces a well-formed metadata document with no
    # dependencies at all: the silent success the file-based producers above
    # exist to close.
    edge_status=0
    rg -N -o -r '${1}|${2}${3}' \
        '^(fixture-[a-h]) = (?:"([^"]+)"|\{ version = "([^"]+)"[^}]*\})$' \
        "${package_manifest}" > "${state}/edges.txt" || edge_status=$?
    if [ "${edge_status}" -eq 1 ]; then
        : > "${state}/edges.txt"
    elif [ "${edge_status}" -ne 0 ]; then
        refuse "could not search ${package_manifest} for its edges (rg exited ${edge_status})"
    fi
    jq -n \
        --arg name "${package_name}" \
        --arg version "${package_version}" \
        --arg manifest "${package_manifest}" \
        --arg directory "${package_directory}" \
        --rawfile edges "${state}/edges.txt" \
        '{name: $name,
          version: $version,
          source: null,
          manifest_path: $manifest,
          id: ("path+file://" + $directory + "#" + $name + "@" + $version),
          dependencies: ($edges
              | split("\n")
              | map(select(length > 0)
                    | split("|")
                    | {name: .[0], req: ("^" + .[1]), kind: null}))}'
}

# One workspace as `cargo metadata` describes it, resolved edges included.
workspace_json() {
    workspace_manifest="$1"
    workspace_directory=$(dirname "${workspace_manifest}")
    : > "${state}/packages.json"
    for member in "${workspace_directory}"/*/Cargo.toml; do
        package_json "${member}" >> "${state}/packages.json"
    done
    jq -s '. as $all
        | ($all | map({key: .name, value: .id}) | from_entries) as $ids
        | {packages: $all,
           workspace_members: ($all | map(.id)),
           resolve: {nodes: ($all | map({id: .id,
               deps: (.dependencies | map({name: .name, pkg: $ids[.name]}))}))}}' \
        "${state}/packages.json"
}

if [ "${FAKE_FAULT_OPERATION:-}" = "${operation}" ]; then
    case "${FAKE_FAULT_MODE:-}" in
        ordinary)
            printf '%s\n' "${FAKE_FAULT_SAMPLE}" >&2
            exit "${FAKE_FAULT_STATUS}"
            ;;
        infrastructure)
            printf '%s\n' "${FAKE_FAULT_SAMPLE}" >&2
            exit 1
            ;;
        interrupt)
            sleep 60 &
            printf '%s\n' "$!" >> "${state}/pids"
            kill -TERM "${PPID}"
            exit 0
            ;;
        *)
            refuse "was given the unknown fault mode [${FAKE_FAULT_MODE:-}]"
            ;;
    esac
fi

case "${operation}" in
    install)
        require --root "${install_root}"
        # A registry installation names its crate last; a local one names the
        # tree it builds, and the package that tree declares is what the
        # installed binary is called. Reading the name out of that manifest is
        # what keeps the journey's installation an installation of whatever the
        # proof pointed it at, rather than of a name this fake decided.
        installed="${last_argument}"
        if [ -n "${package_path}" ]; then
            installed=$(rg -N -o -r '${1}' '^name = "([^"]+)"$' "${package_path}/Cargo.toml")
        fi
        mkdir -p "${install_root}/bin"
        cp "${FAKE_TOOL_BODIES}/${installed}" "${install_root}/bin/${installed}"
        chmod +x "${install_root}/bin/${installed}"
        log "install ${installed}"
        ;;
    package)
        require --manifest-path "${manifest}"
        # Real `cargo package --locked` refuses a tree carrying uncommitted
        # changes, so the archives can only ever hold what the proof committed.
        # The staging commit for the release-plz update is what makes that tree
        # clean; without it the real tool refuses here, and so does this one.
        clone_root=$(dirname "${manifest}")
        # Captured before it is tested rather than read inside the test. A `git`
        # that failed inside `[ -n "$(...)" ]` reports its status to the
        # substitution and leaves the test an empty string, so a tree this fake
        # could not read would package as a clean one — the same silent success
        # the file-based producers above exist to close. An assignment is what
        # `set -e` sees.
        uncommitted=$(git -C "${clone_root}" status --porcelain --untracked-files=all)
        if [ -n "${uncommitted}" ]; then
            printf 'error: %s\n' \
                'files in the working directory contain changes that were not yet committed into git' \
                >&2
            exit 101
        fi
        # What the archives are built onto, newest first, so a row reads the
        # isolated history rather than inferring it from an archive that would
        # have been written either way.
        git -C "${clone_root}" log --format='package onto %s' >> "${state}/operations"
        for member in "${clone_root}"/*/Cargo.toml; do
            package_name=$(rg -N -o -r '${1}' '^name = "([^"]+)"$' "${member}")
            package_version=$(rg -N -o -r '${1}' '^version = "([^"]+)"$' "${member}")
            staging="${state}/pack/${package_name}-${package_version}"
            rm -rf "${staging}"
            mkdir -p "${staging}/src"
            cp "${member}" "${staging}/Cargo.toml"
            cp "$(dirname "${member}")/src/lib.rs" "${staging}/src/lib.rs"
            mkdir -p "${CARGO_TARGET_DIR}/package"
            tar -czf "${CARGO_TARGET_DIR}/package/${package_name}-${package_version}.crate" \
                -C "${state}/pack" "${package_name}-${package_version}"
            log "package ${package_name}"
        done
        ;;
    metadata)
        require --manifest-path "${manifest}"
        if [ "${no_deps}" -eq 1 ]; then
            if [ -f "$(dirname "${manifest}")/release-plz.toml" ]; then
                log "metadata staged"
                workspace_json "${manifest}"
            else
                extracted=$(rg -N -o -r '${1}' '^name = "([^"]+)"$' "${manifest}")
                log "metadata extracted ${extracted}"
                package_json "${manifest}" > "${state}/metadata.json"
                jq -s '{packages: .}' "${state}/metadata.json"
            fi
        else
            # The one reading the graph refusals judge. A row that wants a
            # refusal supplies the jq filter that breaks the graph, or the
            # warning Cargo prints when a patch redirects nothing.
            #
            # The manifest is kept beside the record because the proof writes it
            # into a staging root it then removes, and its member list and patch
            # table are what a row reads to say the archives — rather than the
            # registry — answered for every first-party requirement.
            log "metadata archive"
            cp -- "${manifest}" "${state}/archive-manifest.toml"
            if [ -n "${FAKE_METADATA_WARNING:-}" ]; then
                printf '%s\n' "${FAKE_METADATA_WARNING}" >&2
            fi
            workspace_json "${manifest}" > "${state}/metadata.json"
            jq "${FAKE_GRAPH_MUTATION:-.}" "${state}/metadata.json"
        fi
        ;;
    generate-lockfile)
        require --manifest-path "${manifest}"
        printf '# fixture lock\n' > "$(dirname "${manifest}")/Cargo.lock"
        log "generate-lockfile"
        ;;
    check)
        require --manifest-path "${manifest}"
        log "check"
        ;;
    *)
        refuse "does not implement [${operation} $*]"
        ;;
esac
