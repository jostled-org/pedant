#!/bin/sh
# The stand-in Cargo one packaged-workspace lifecycle row installs on PATH.
#
# It implements the whole operation protocol the tracked proof drives, records
# the target root every call inherited and the process ids it owns, and injects
# at most one fault. It compiles nothing: a row proves the proof's lifecycle,
# not Cargo's.

set -eu

state="${FAKE_STATE_DIR}"
printf '%s\n' "$$" >> "${state}/pids"
printf '%s\n' "${CARGO_TARGET_DIR:-}" >> "${state}/targets"

operation="$1"
shift

manifest=""
install_root=""
last_argument=""
no_deps=0
previous=""
for argument in "$@"; do
    case "${previous}" in
        --manifest-path) manifest="${argument}" ;;
        --root) install_root="${argument}" ;;
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

# One manifest as `cargo metadata` describes it, with its first-party edges.
package_json() {
    package_manifest="$1"
    package_directory=$(dirname "${package_manifest}")
    package_name=$(rg -N -o -r '${1}' '^name = "([^"]+)"$' "${package_manifest}")
    package_version=$(rg -N -o -r '${1}' '^version = "([^"]+)"$' "${package_manifest}")
    if ! rg -N -o -r '${1}|${2}' '^(fixture-[a-h]) = "([^"]+)"$' "${package_manifest}" \
        > "${state}/edges.txt"; then
        : > "${state}/edges.txt"
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
    esac
fi

case "${operation}" in
    install)
        mkdir -p "${install_root}/bin"
        cp "${FAKE_TOOL_BODIES}/${last_argument}" "${install_root}/bin/${last_argument}"
        chmod +x "${install_root}/bin/${last_argument}"
        log "install ${last_argument}"
        ;;
    package)
        for member in "$(dirname "${manifest}")"/*/Cargo.toml; do
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
        if [ "${no_deps}" -eq 1 ]; then
            if [ -f "$(dirname "${manifest}")/release-plz.toml" ]; then
                log "metadata staged"
                workspace_json "${manifest}"
            else
                extracted=$(rg -N -o -r '${1}' '^name = "([^"]+)"$' "${manifest}")
                log "metadata extracted ${extracted}"
                package_json "${manifest}" | jq -s '{packages: .}'
            fi
        else
            log "metadata archive"
            workspace_json "${manifest}"
        fi
        ;;
    generate-lockfile)
        printf '# fixture lock\n' > "$(dirname "${manifest}")/Cargo.lock"
        log "generate-lockfile"
        ;;
    check)
        log "check"
        ;;
    *)
        printf 'error: the fake cargo does not implement %s\n' "${operation}" >&2
        exit 2
        ;;
esac
