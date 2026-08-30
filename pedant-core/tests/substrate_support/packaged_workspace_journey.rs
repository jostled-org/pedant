//! 12.T4 (Invariant 22): the archive proof registers the packaged snippet
//! journey.
//!
//! Compiling eight archives says the release links. It does not say the
//! navigation product an operator installs from those archives can index a
//! repository and answer a question, and that is the one thing this release is
//! for. The proof therefore installs the packaged binary out of the generated
//! workspace, points it at a mixed-language repository it wrote outside the
//! checkout, and drives both transports over it.
//!
//! This module states that the proof is registered to do that. It does not
//! claim the journey ran: the run costs a registry, two pinned tools, and a
//! quarter of an hour, and belongs to the indexed `packaged-workspace-verify`
//! command. What a scoped test can own is that the expensive proof cannot
//! silently stop being that journey — that it cannot install from the checkout,
//! ask about a tree it never wrote, drop a transport, or accept a listing that
//! serves something other than the eight tools this product publishes.

use crate::packaged_workspace_reading::packaged_workspace_script;
use crate::shell_script_reading::{assert_contains_all, assert_in_order, function_body};

/// The navigation product the journey installs, as the proof names it.
///
/// Three spellings, because they are three facts: which released package
/// carries the journey, which binary that package installs, and how many tools
/// that binary serves. A proof that took the package name for the binary name
/// would look right in this workspace and break on the first product whose
/// binary is not its package, and one that took the release's package count for
/// the tool count would refuse a correct eight-tool listing on the day a ninth
/// package is published.
const NAVIGATION_IDENTITY: &[&str] = &[
    "NAVIGATION_PACKAGE=\"pedant-snippet\"",
    "NAVIGATION_BINARY=\"pedant-snippet\"",
    "NAVIGATION_TOOL_COUNT=8",
];

/// The stages the journey runs, in the order it runs them.
///
/// Read inside the one function that calls them. A binary installed after the
/// questions were asked would answer none of them, and a fixture written after
/// the install is still a fixture the install never needed — but a journey that
/// asked its questions before it wrote the repository would ask them about an
/// empty directory and read the refusal as an answer.
///
/// The leak refusal closes the sequence, and its place there is the claim. It
/// reads what the journey collected, so it can only run once both transports
/// have answered — and a refusal that is defined but never called is a guard
/// this proof does not have.
const JOURNEY_STAGE_SEQUENCE: &[&str] = &[
    "write_journey_repository",
    "install_packaged_snippet",
    "assert_packaged_cli_journey",
    "assert_packaged_mcp_journey",
    "assert_no_checkout_leakage",
];

/// Where the installed binary comes from, and what it has to be.
///
/// The `--path` is the extracted archive member, so the binary an operator gets
/// from crates.io is the binary this journey runs; `--locked` holds it to the
/// lockfile the archive graph was resolved with; and the version assertion is
/// what makes the answer below this run's rather than an operator's own
/// installation earlier on `PATH`.
const PACKAGED_INSTALL_STEPS: &[&str] = &[
    "run_classified journey-install env \"CARGO_PROFILE_DEV_DEBUG=0\" cargo install \
     --path \"${workspace_root}/${NAVIGATION_PACKAGE}-${staged_version}\" \
     --root \"${journey_install_root}\" --debug --locked",
    "assert_tool_version \"${journey_binary}\" \"${staged_version}\" --version",
];

/// Every source the journey repository holds, one per admitted language plus
/// the three project authorities.
///
/// The whole table is the claim. This build links six grammars and both graph
/// producers, and a fixture of one language would let a packaged binary that
/// lost five of them pass the journey unchanged.
const JOURNEY_FIXTURE_SOURCES: &[&str] = &[
    "${journey_root}/Cargo.toml",
    "${journey_root}/crate-a/Cargo.toml",
    "${journey_root}/crate-a/src/lib.rs",
    "${journey_root}/crate-a/src/main.rs",
    "${journey_root}/go.mod",
    "${journey_root}/main.go",
    "${journey_root}/scripts/tool.py",
    "${journey_root}/scripts/tool.sh",
    "${journey_root}/web/app.js",
    "${journey_root}/web/app.ts",
];

/// Every question the CLI journey asks, in order.
///
/// The nine commands this product publishes less the server, which the MCP
/// journey owns. A journey that asked only the cheap ones would leave the graph
/// commands — the ones whose feature closure the archive install is most likely
/// to have dropped — unasked.
const JOURNEY_QUESTIONS: &[&str] = &[
    "ask_journey projects list-projects",
    "ask_journey search search make --mode exact --language rust",
    "ask_journey entry search main --mode exact --language rust",
    "ask_journey outline outline crate-a/src/lib.rs",
    "ask_journey read read \"${journey_revision}\" \"${make_id}\"",
    "ask_journey at at main.go 5",
    "ask_journey relations relations \"${journey_revision}\" \"${main_id}\" \
     --direction outgoing --max-depth 2 --edge-kind call --certainty resolved",
    "ask_journey path path \"${journey_revision}\" \"${main_id}\" \
     \"${journey_revision}\" \"${make_id}\" --edge-kind call --certainty resolved",
    "ask_journey analysis graph \"${journey_revision}\" \"${project_id}\" components \
     --edge-kind call --certainty resolved",
];

/// What each of those answers has to say.
///
/// One field per question, and never only the exit status: a binary that
/// printed an empty envelope for everything would answer zero to all nine.
const JOURNEY_EXPECTATIONS: &[&str] = &[
    "assert_journey_field projects '[.result[].language] | sort | unique | join(\",\")' \"go,rust\"",
    "assert_journey_field search '.result | length' 1",
    "assert_journey_field entry '.result | length' 1",
    "assert_journey_field outline '.result.structures | length' 1",
    "assert_journey_field read '.result.structure.qualified_name' \
     \"crate-a/src/lib.rs::make\"",
    "assert_journey_field at '.result.structure.qualified_name' \"main.go::New\"",
    "assert_journey_field relations '[.result[].edges[].kind] | join(\",\")' call",
    "assert_journey_field path '.result.selected.edges | length' 1",
    "assert_journey_field analysis '.result.mode' components",
];

/// The one index every answer of one journey is about.
///
/// The first question states the revision and every later one has to agree with
/// it. Nine processes indexing one tree either state one identity or the
/// identity is not the repository's, and no single answer can say which.
///
/// Read inside the function that asks the questions. The same block sitting
/// anywhere in the script would agree with nothing: an agreement moved out of
/// `ask_journey` into a function nobody calls leaves nine answers unreconciled
/// and reads, from the whole file, exactly like one that runs.
const JOURNEY_INDEX_AGREEMENT: &[&str] = &[
    "case \"${journey_revision}\" in",
    "\"\") journey_revision=\"${stated}\" ;;",
    "\"${stated}\") ;;",
    "*) fail \"the ${label} answer states index ${stated}",
];

/// The four messages the packaged server is driven with, in protocol order.
const MCP_JOURNEY_REQUESTS: &[&str] = &[
    "\"method\":\"initialize\"",
    "\"method\":\"notifications/initialized\"",
    "\"method\":\"tools/list\"",
    "\"method\":\"tools/call\"",
];

/// The eight tools the packaged listing has to serve, as one joined line.
///
/// The whole listing rather than a membership check, because a build that lost
/// its graph features serves five of these and would satisfy any check that
/// asked whether the ones it kept were present.
const SERVED_TOOLS: &str = "list_projects,search_symbols,outline_file,read_structure,\
                            structure_at,query_relations,find_path,analyze_graph";

/// What the MCP journey requires of the answers it gets back.
///
/// The listing, the read-only annotations every published tool carries, the
/// call that did not fail, and the bytes that call returned — which have to be
/// the bytes the CLI printed for the same question. Parity is the claim the
/// other three cannot make: two transports that each answer plausibly and
/// differently are two products.
const MCP_JOURNEY_EXPECTATIONS: &[&str] = &[
    "select(.id == 2) | [.result.tools[].name] | join(\",\")",
    "select(.id == 2) | [.result.tools[] | select(.annotations.readOnlyHint == true \
     and .annotations.idempotentHint == true and .annotations.openWorldHint == false)] | length",
    "select(.id == 3) | .result.isError",
    "select(.id == 3) | .result.content[0].text",
];

/// The refusal that keeps the journey outside the checkout.
const CHECKOUT_LEAK_REFUSAL: &str = "names the original checkout";

/// 12.T4 (Invariant 22): the tracked archive proof installs the packaged
/// navigation binary out of the archives and completes both transports over one
/// mixed-language repository it owns.
#[test]
fn packaged_snippet_journey_is_registered_in_archive_proof() {
    let script = packaged_workspace_script();
    let (source, joined) = (script.source, script.joined);

    assert_the_navigation_product_is_named_and_required(source, joined);
    assert_the_journey_runs_its_stages_in_order(joined);
    assert_the_binary_comes_from_the_archive(joined);
    assert_the_repository_is_written_outside_the_checkout(joined);
    assert_every_question_is_asked_and_read(joined);
    assert_both_transports_answer_the_same_index(joined);
}

/// The proof names the navigation package once and refuses a release order
/// without it before it changes any state.
///
/// The refusal is early because it is cheap and the alternative is not: a
/// release whose order lost this package would otherwise clone, build two
/// pinned tools, stage, and package all eight archives before discovering that
/// the journey has no subject.
fn assert_the_navigation_product_is_named_and_required(source: &str, joined: &str) {
    assert_contains_all(joined, NAVIGATION_IDENTITY, "the navigation product");
    let preflight = function_body(joined, "read_release_order");
    assert!(
        preflight.contains("assert_release_order_names_the_navigation_product"),
        "the release order is required to name the navigation product before anything is staged"
    );
    let named = function_body(source, "assert_release_order_names_the_navigation_product");
    assert!(
        named.contains("${NAVIGATION_PACKAGE}"),
        "the navigation-product check reads the package the proof named"
    );
    assert!(
        named.contains("fail "),
        "a release order without the navigation product is a refusal rather than a skipped journey"
    );
}

/// The journey runs its own stages in the order it needs them.
///
/// That the journey itself follows the packaged graph is not read here.
/// [`crate::packaged_workspace`] takes the whole proof sequence over the entry
/// point's body, and `verify_packaged_graph` and `run_packaged_snippet_journey`
/// are adjacent entries in it — so a second offset comparison over that same
/// body would be a second owner of one ordering claim.
fn assert_the_journey_runs_its_stages_in_order(joined: &str) {
    assert_in_order(
        &function_body(joined, "run_packaged_snippet_journey"),
        JOURNEY_STAGE_SEQUENCE,
        "the packaged snippet journey",
    );
}

/// The binary is installed from the extracted archive member into the staging
/// root, under the lockfile the archive graph was resolved with, and is then
/// required to be the version release-plz staged.
fn assert_the_binary_comes_from_the_archive(joined: &str) {
    assert_in_order(
        &function_body(joined, "install_packaged_snippet"),
        PACKAGED_INSTALL_STEPS,
        "the packaged install",
    );
    assert!(
        joined.contains("journey_install_root=\"${staging_root}/install\""),
        "the install root is inside the staging root this run releases"
    );
    assert!(
        joined.contains("journey_binary=\"${journey_install_root}/bin/${NAVIGATION_BINARY}\""),
        "the journey runs the binary that installation produced"
    );
}

/// The repository the journey asks about is written beneath the staging root
/// and holds every language this build links.
fn assert_the_repository_is_written_outside_the_checkout(joined: &str) {
    assert!(
        joined.contains("journey_root=\"${staging_root}/journey\""),
        "the journey repository is this run's own, outside the caller's checkout"
    );
    assert_contains_all(
        &function_body(joined, "write_journey_repository"),
        JOURNEY_FIXTURE_SOURCES,
        "the journey repository",
    );
    assert!(
        function_body(joined, "ask_journey").contains("--root \"${journey_root}\""),
        "every question is asked about the repository the journey wrote"
    );
    assert!(
        function_body(joined, "assert_no_checkout_leakage").contains(CHECKOUT_LEAK_REFUSAL),
        "an answer naming the caller's checkout is refused"
    );
}

/// Every modelled question is asked, in order, and every answer is read for the
/// one field it exists to state.
fn assert_every_question_is_asked_and_read(joined: &str) {
    // The two tables are held equal here rather than in prose. "One field per
    // question" was written above the answers and was false at eight rows
    // against nine: the `entry` question's answer went unread, and an empty
    // envelope there only failed two questions later, under another question's
    // name. A doc sentence cannot count its own rows.
    assert_eq!(
        JOURNEY_EXPECTATIONS.len(),
        JOURNEY_QUESTIONS.len(),
        "the journey asks {} questions and reads {} answers, so some answer is never read",
        JOURNEY_QUESTIONS.len(),
        JOURNEY_EXPECTATIONS.len()
    );
    let body = function_body(joined, "assert_packaged_cli_journey");
    assert_in_order(&body, JOURNEY_QUESTIONS, "the CLI journey");
    assert_contains_all(&body, JOURNEY_EXPECTATIONS, "the CLI journey's answers");
}

/// Both transports are driven over the same repository, and the server's answer
/// is the CLI's answer.
fn assert_both_transports_answer_the_same_index(joined: &str) {
    assert_contains_all(
        &function_body(joined, "ask_journey"),
        JOURNEY_INDEX_AGREEMENT,
        "the journey's one index",
    );
    let body = function_body(joined, "assert_packaged_mcp_journey");
    assert_contains_all(&body, MCP_JOURNEY_REQUESTS, "the MCP journey's requests");
    assert_contains_all(&body, MCP_JOURNEY_EXPECTATIONS, "the MCP journey's answers");
    assert!(
        body.contains(SERVED_TOOLS),
        "the packaged listing serves exactly [{SERVED_TOOLS}]"
    );
    assert!(
        body.contains("test \"${served}\" = \"${NAVIGATION_TOOL_COUNT}\""),
        "the annotated tools are counted against this product's tool count rather \
         than the release's package count"
    );
    assert!(
        body.contains("test \"${served}\" = \"false\""),
        "the packaged server's own listed tool is required to have answered without an error"
    );
    assert!(
        body.contains("test \"${served}\" = \"${cli}\""),
        "the server's answer is required to be the bytes the CLI printed"
    );
}
