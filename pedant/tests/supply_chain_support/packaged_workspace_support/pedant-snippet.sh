#!/bin/sh
# The stand-in navigation product one packaged-workspace lifecycle row installs
# out of its own archive.
#
# The tracked proof installs this product from the generated archive workspace
# and asks it every question it publishes, over the command line and over a real
# stdio MCP session. What a row owns is the script's lifecycle around that
# journey — that it installed from the archive, wrote the repository it asks
# about, drove both transports in the order it states, and released everything
# it owns afterwards. So this binary compiles nothing, indexes nothing, and
# answers with canned documents; the indexed proof runs the real one.
#
# It is not a steady fake. It refuses a root that does not hold the repository
# the proof is required to have written, and it refuses a session that is not
# the four messages the proof is required to send — so a script that stopped
# writing that repository, or stopped sending that session, fails a row instead
# of reading its own omission back as an answer.

set -eu

state="${FAKE_STATE_DIR}"
printf '%s\n' "$$" >> "${state}/pids"

# The version the fixture's release-plz stages, which is what the proof requires
# the binary it just installed to report.
VERSION="0.2.0"

# The one index every canned answer is stated from, so the proof's own reading —
# that nine separate processes agreed about one repository — has something to
# agree on.
REVISION="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# Every tool this product's registry serves, in listing order.
TOOLS="list_projects search_symbols outline_file read_structure structure_at \
query_relations find_path analyze_graph"

log() {
    printf 'snippet %s\n' "$1" >> "${state}/operations"
}

refuse() {
    printf 'error: the fake pedant-snippet %s\n' "$1" >&2
    exit 2
}

# One answer, in the envelope every navigation response travels in.
envelope() {
    printf '{"index_revision":"%s","state_revision":"%s","health":"current","result":%s}\n' \
        "${REVISION}" "${REVISION}" "$1"
}

# The repository the proof is required to have written, proved present.
#
# Two files rather than the directory, because a directory is what an empty
# `mkdir -p` leaves and a journey asked about one would be a journey about
# nothing.
require_fixture() {
    root=""
    previous=""
    for argument in "$@"; do
        case "${previous}" in
            --root) root="${argument}" ;;
        esac
        previous="${argument}"
    done
    if [ ! -f "${root}/crate-a/Cargo.toml" ] || [ ! -f "${root}/main.go" ]; then
        refuse "was asked about [${root}], which holds no journey repository"
    fi
}

# The three project slices a two-authority repository resolves.
projects_result() {
    printf '[{"handle":{"revision":"%s","id":0},"language":"rust",' "${REVISION}"
    printf '"unit":"crate-a::bin::crate-a"},'
    printf '{"handle":{"revision":"%s","id":1},"language":"rust",' "${REVISION}"
    printf '"unit":"crate-a::lib::crate_a"},'
    printf '{"handle":{"revision":"%s","id":2},"language":"go",' "${REVISION}"
    printf '"unit":"example.com/main"}]'
}

# One named structure, as a search states it.
structure_result() {
    printf '[{"handle":{"revision":"%s","id":%s},"qualified_name":"%s"}]' \
        "${REVISION}" "$1" "$2"
}

# One structure and the source it covers, as a read or a point lookup states it.
structure_source() {
    printf '{"structure":{"qualified_name":"%s"},"text":"%s"}' "$1" "$2"
}

# Every served definition, with the annotations a published tool carries.
tools_json() {
    separator=""
    printf '['
    for name in ${TOOLS}; do
        printf '%s{"name":"%s","annotations":' "${separator}" "${name}"
        printf '{"readOnlyHint":true,"idempotentHint":true,"openWorldHint":false}}'
        separator=","
    done
    printf ']'
}

# One stdio session: the four messages the proof sends, answered in order.
serve() {
    session="$(cat)"
    for method in initialize notifications/initialized tools/list tools/call; do
        case "${session}" in
            *"\"method\":\"${method}\""*) ;;
            *) refuse "received no ${method} request" ;;
        esac
    done
    jq -c -n --arg version "${VERSION}" \
        '{jsonrpc:"2.0",id:1,result:{protocolVersion:"2025-06-18",capabilities:{tools:{}},
          serverInfo:{name:"pedant-snippet",version:$version}}}'
    jq -c -n --argjson tools "$(tools_json)" '{jsonrpc:"2.0",id:2,result:{tools:$tools}}'
    jq -c -n --arg text "$(envelope "$(projects_result)")" \
        '{jsonrpc:"2.0",id:3,result:{content:[{type:"text",text:$text}],isError:false}}'
}

case "${1:-}" in
    --version)
        # The one line this body writes in the pinned tools' shape rather than
        # its own, because it answers the same question they do: the proof asks
        # a binary it just installed to say which build it is, and a row reads
        # that probe the same way for all three.
        printf 'version pedant-snippet\n' >> "${state}/operations"
        printf 'pedant-snippet %s\n' "${VERSION}"
        ;;
    list-projects)
        require_fixture "$@"
        log list-projects
        envelope "$(projects_result)"
        ;;
    search)
        require_fixture "$@"
        log search
        case "${2:-}" in
            make) envelope "$(structure_result 0 'crate-a/src/lib.rs::make')" ;;
            main) envelope "$(structure_result 1 'crate-a/src/main.rs::main')" ;;
            *) refuse "does not implement the search [${2:-}]" ;;
        esac
        ;;
    outline)
        require_fixture "$@"
        log outline
        envelope '{"path":"crate-a/src/lib.rs","language":"rust","structures":[{"id":0}]}'
        ;;
    read)
        require_fixture "$@"
        log read
        envelope "$(structure_source 'crate-a/src/lib.rs::make' 'pub fn make() -> u8 {}')"
        ;;
    at)
        require_fixture "$@"
        log at
        envelope "$(structure_source 'main.go::New' 'func New(name string) *Node {}')"
        ;;
    relations)
        require_fixture "$@"
        log relations
        envelope '[{"seed":4,"edges":[{"kind":"call"}]}]'
        ;;
    path)
        require_fixture "$@"
        log path
        envelope '{"selected":{"edges":[{"id":1,"kind":"call"}]}}'
        ;;
    graph)
        require_fixture "$@"
        log graph
        envelope '{"mode":"components","answer":[]}'
        ;;
    mcp)
        require_fixture "$@"
        log mcp
        serve
        ;;
    *)
        refuse "does not implement [$*]"
        ;;
esac
