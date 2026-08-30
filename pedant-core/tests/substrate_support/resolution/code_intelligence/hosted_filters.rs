//! 10.T4 (Invariant 23, Exit Criterion 2): every `--exact` filter the tracked
//! workflow runs selects one test this workspace registers.
//!
//! `cargo test … <filter> -- --exact` matches the whole libtest name, and that
//! name is the module path the executable registers the function under. A filter
//! that stops resolving does not fail. It prints `0 filtered out`, exits 0, and
//! the job that ran it is reported `completed success` — so a receipt that reads
//! that job certifies behavior nothing executed.
//!
//! The two hosted jobs are where that costs the most: Windows job-object
//! containment, stdio framing, and path serialization are claims no Linux runner
//! and no local machine can answer. Renaming `journeys::platform`, or moving the
//! predicate behind a feature the job does not select, leaves every text-level
//! reading of the workflow green while the command selects nothing.
//!
//! This reading refuses it in the ordinary workspace suite before the final
//! plan commit is created. Hosted CI then executes the same registered filters
//! after that final commit is pushed.
//!
//! The claim covers every exact filter in the workflow rather than the hosted
//! two, because the hazard is the command shape and not the runner: four other
//! run lines pin a single predicate the same way. The tracked platform harness
//! separately binds each requirement to the job that owns it.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::path::Path;

use crate::resolution::authority_scan::read_text;
use crate::resolution::code_intelligence::hosted_filter_model::{
    ExactFilter, ExactRun, PROFILE_GATE, WORKFLOW_EXACT_FILTERS, exact_runs,
};
use crate::resolution::comment_scan::code_index;
use crate::resolution::fixture::{FixtureFile, build_repository};
use crate::resolution::manifest_reader::{default_features, manifest_table};
use crate::resolution::root_inventory::{INTEGRATION_ROOTS, workspace_root};
use crate::resolution::test_identity::{
    Gate, Selection, declaration_sites, filter_selection, workspace_test_sources,
};
use crate::resolution::tracked_script::CI_WORKFLOW;

/// Every exact filter the tracked workflow runs is the identity of a predicate
/// this workspace registers, at the file the model names, under the profile the
/// run line asks for.
pub(crate) fn assert_every_workflow_exact_filter_selects_a_registered_test() {
    assert_the_workflow_runs_exactly_the_modelled_filters();
    assert_every_modelled_filter_selects_its_owner();
    assert_a_filter_that_selects_nothing_refuses();
}

/// The workflow's exact invocations are exactly the modelled ones.
///
/// Set equality rather than membership. A membership check agrees with a
/// workflow that grew a seventh exact filter naming nothing, which is the same
/// silent success one rank down.
///
/// Two empty sets are equal, and that is the one shape set equality cannot
/// reject on its own: a workflow whose `--exact` lines were reworded past
/// [`exact_runs`]' selector reads as stating none, an emptied model agrees with
/// it, and the resolution loop below then walks no row. The floor is asserted on
/// the parsed workflow rather than on the table, because the workflow is the
/// subject and the equality carries the floor across to the model.
fn assert_the_workflow_runs_exactly_the_modelled_filters() {
    let workflow = read_text(CI_WORKFLOW);
    let stated: BTreeSet<ExactRun> = exact_runs(&workflow)
        .unwrap_or_else(|error| panic!("{CI_WORKFLOW}: {error}"))
        .into_vec()
        .into_iter()
        .collect();
    assert!(
        !stated.is_empty(),
        "{CI_WORKFLOW} states no `-- --exact` run line, so every claim over the filters it runs \
         is vacuous"
    );
    let modelled: BTreeSet<ExactRun> = WORKFLOW_EXACT_FILTERS
        .iter()
        .map(ExactFilter::stated_run)
        .collect();
    assert_eq!(
        stated, modelled,
        "{CI_WORKFLOW} must run exactly the modelled exact filters"
    );
}

/// Each modelled filter resolves through the declarations its target root makes,
/// is live under the profile its run line selects, and lands on the one file
/// that declares it.
fn assert_every_modelled_filter_selects_its_owner() {
    let sources = workspace_test_sources();
    let profile = profile_gate_features();
    for row in WORKFLOW_EXACT_FILTERS {
        let target_root = format!("{}/tests/{}.rs", row.package, row.target);
        assert!(
            INTEGRATION_ROOTS.contains(&&*target_root),
            "{target_root} must be a modelled integration executable to answer an exact filter"
        );
        let selection = answer(
            &workspace_root(),
            &target_root,
            row.filter,
            &selected_features(row),
            &profile,
        )
        .unwrap_or_else(|error| panic!("{CI_WORKFLOW} runs `{}`, and {error}", row.filter));
        assert_eq!(
            &*selection.file, row.owner,
            "{} must select its predicate from the modelled owner",
            row.filter
        );
        let leaf = &selection.leaf;
        let sites = declaration_sites(sources, leaf);
        assert_eq!(
            &*sites,
            &[row.owner][..],
            "{leaf} must be declared once in the whole workspace, at its modelled owner"
        );
    }
}

/// The selection one filter makes on a live registered test, or why it selects
/// nothing.
///
/// One implementation, two callers: the modelled rows above and the broken trees
/// below. A second walk for the refusals would prove a walk nothing runs.
///
/// The whole selection is returned rather than its file alone. The caller above
/// needs the leaf too, and handing back only the file left it splitting the
/// filter a second time to find one the walk had already read.
fn answer(
    root: &Path,
    target_root: &str,
    filter: &str,
    selected: &BTreeSet<String>,
    profile: &BTreeSet<String>,
) -> Result<Selection, String> {
    let selection = filter_selection(root, target_root, filter)?;
    price(&selection.gates, selected, profile)?;
    Ok(selection)
}

/// Every conditional between the target root and the declaration is satisfied by
/// the features the run line selects.
fn price(
    gates: &[Gate],
    selected: &BTreeSet<String>,
    profile: &BTreeSet<String>,
) -> Result<(), String> {
    for gate in gates {
        let required = required_features(gate, profile)?;
        let missing: Box<[&String]> = required
            .iter()
            .filter(|feature| !selected.contains(*feature))
            .collect();
        match missing.is_empty() {
            true => (),
            false => {
                return Err(format!(
                    "it sits behind {missing:?}, which the run line does not select"
                ));
            }
        }
    }
    Ok(())
}

/// What one gate asks of the profile.
///
/// Borrowed for the profile gate, which asks for the caller's own set and is
/// asked once per gate on every priced row. Only the `cfg` arm derives a set of
/// its own, and only that arm owns one.
fn required_features<'profile>(
    gate: &Gate,
    profile: &'profile BTreeSet<String>,
) -> Result<Cow<'profile, BTreeSet<String>>, String> {
    match gate {
        Gate::Profile => Ok(Cow::Borrowed(profile)),
        Gate::Cfg(attribute) => cfg_features(attribute).map(Cow::Owned),
    }
}

/// Every feature one `#[cfg(...)]` requires, or why it cannot be priced.
///
/// A single `feature = "..."` and an `all(...)` of them are read, and nothing
/// else is. `any`, `not`, and every platform predicate refuse rather than
/// resolve: `#[cfg(unix)]` over a hosted predicate is a Windows job that selects
/// nothing, and a walk that read it as asking for no feature would call that
/// live.
fn cfg_features(attribute: &str) -> Result<BTreeSet<String>, String> {
    let body = attribute
        .strip_prefix("#[cfg(")
        .and_then(|rest| rest.strip_suffix(")]"))
        .ok_or_else(|| format!("{attribute} is not a cfg attribute this walk can price"))?;
    let terms = body
        .strip_prefix("all(")
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or(body);
    terms
        .split(',')
        .map(str::trim)
        .filter(|term| !term.is_empty())
        .map(one_feature)
        .collect()
}

fn one_feature(term: &str) -> Result<String, String> {
    term.strip_prefix("feature = \"")
        .and_then(|rest| rest.strip_suffix('"'))
        .map(str::to_owned)
        .ok_or_else(|| {
            format!("{term} is not a feature selection, so no profile can be said to satisfy it")
        })
}

/// Everything one run line's profile selects: the package's defaults, plus what
/// the line names.
///
/// Asked of [`manifest_table`] per row rather than through a memo of this
/// module's own. Six rows name three packages, and the per-package map that
/// used to sit here existed only because the manifest reader read and parsed on
/// every call; the reader caches by path now, so the memo was a second cache
/// over the first.
fn selected_features(row: &ExactFilter) -> BTreeSet<String> {
    let manifest = manifest_table(&format!("{}/Cargo.toml", row.package));
    default_features(manifest)
        .iter()
        .map(|feature| (*feature).to_owned())
        .chain(row.features.iter().map(|it| (*it).to_owned()))
        .collect()
}

/// Every feature the shared profile gate requires.
///
/// Empty would make every gated row free, so an empty reading is the error it
/// looks like rather than a claim that passes.
///
/// What a feature selection is, is [`one_feature`]'s answer and not a second one
/// here. The gate file writes its terms one per line inside a `cfg`, so the
/// trailing comma is the only difference from a term the pricing path reads, and
/// a line that is no feature term at all — the `#[cfg(all(` that opens the list,
/// the `)]` that closes it — is discarded rather than guessed at. Two readers of
/// `feature = "..."` could disagree about a spelling this file writes and the
/// other prices.
///
/// Read through [`code_index`] rather than off the page, because a discard is
/// what a comment hides behind. A term annotated where it stands —
/// `feature = "graph-go", // both grammars` — is no term at all to a reader that
/// takes the raw line, so it drops with the bracket lines and the gate prices as
/// requiring less than it gates. Every feature it lost that way makes a
/// predicate behind that feature read as live, which is the silent success this
/// whole file exists to refuse.
fn profile_gate_features() -> BTreeSet<String> {
    let (_, gate) = PROFILE_GATE;
    let required: BTreeSet<String> = code_index(&read_text(gate))
        .iter()
        .map(|(_, line)| line.trim().trim_end_matches(','))
        .filter_map(|term| one_feature(term).ok())
        .collect();
    assert!(
        !required.is_empty(),
        "{gate} must name the features it gates, or every gated predicate prices as free"
    );
    required
}

// ---------------------------------------------------------------------------
// The same walk, over a tree broken one way at a time.
// ---------------------------------------------------------------------------

/// The fixture's target root, relative to the temporary tree.
const FIXTURE_ROOT: &str = "member/tests/target.rs";

/// The one feature the fixture's run line selects. Its rows are written against
/// this name and `off`, which nothing selects.
const FIXTURE_SELECTED: &str = "on";

/// The fixture tree, as paths and whole texts.
///
/// Both declaration forms this repository writes are here — the root's `#[path]`
/// attribute and a `mod.rs`'s gated macro rows — because a refusal is only worth
/// something if the walk it falsifies is the walk that resolves the real tree.
const FIXTURE_FILES: [FixtureFile; 5] = [
    (
        FIXTURE_ROOT,
        "#[path = \"target_support/outer/mod.rs\"]\nmod outer;\n",
    ),
    (
        "member/tests/target_support/outer/mod.rs",
        "complete_profile_modules!(\n    inner,\n);\n\n#[cfg(feature = \"off\")]\nmod conditional;\n\n#[cfg(unix)]\nmod host;\n",
    ),
    (
        "member/tests/target_support/outer/inner.rs",
        "#[test]\nfn registered() {}\n\n#[cfg(feature = \"on\")]\n#[test]\nfn selected() {}\n\nfn helper() {}\n\n#[cfg(feature = \"off\")]\n#[test]\nfn gated() {}\n\n#[test]\nfn twice() {}\n\n#[test]\nfn twice() {}\n",
    ),
    (
        "member/tests/target_support/outer/conditional.rs",
        "#[test]\nfn conditional_predicate() {}\n",
    ),
    (
        "member/tests/target_support/outer/host.rs",
        "#[test]\nfn host_predicate() {}\n",
    ),
];

/// Each filter the fixture answers, and the file it selects.
const FIXTURE_ANSWERS: [(&str, &str); 2] = [
    (
        "outer::inner::registered",
        "member/tests/target_support/outer/inner.rs",
    ),
    (
        "outer::inner::selected",
        "member/tests/target_support/outer/inner.rs",
    ),
];

/// Each way one `cargo test … -- --exact` prints `0 filtered out`, exits 0, and
/// reports a predicate that never ran — with the phrase the walk must answer.
///
/// The first two rows are the drift this case exists for: a module renamed at
/// either level, with the workflow untouched. Then a leaf that left, a leaf that
/// was never a test, a leaf written twice, and a module-qualified filter reduced
/// to a bare name. The last three are the profile: a predicate and a module
/// behind a feature the run line does not select, and a module behind a
/// conditional no feature list can answer for.
const FIXTURE_REFUSALS: [(&str, &str); 9] = [
    ("outer::moved::registered", "declares no module moved"),
    ("moved::inner::registered", "declares no module moved"),
    ("outer::inner::absent", "registers no test named absent"),
    ("outer::inner::helper", "registers no test named helper"),
    ("outer::inner::twice", "declares twice 2 times"),
    ("registered", "registers no test named registered"),
    ("outer::inner::gated", "which the run line does not select"),
    (
        "outer::conditional::conditional_predicate",
        "which the run line does not select",
    ),
    ("outer::host::host_predicate", "is not a feature selection"),
];

/// The walk resolves a tree it can read and refuses every tree it cannot.
///
/// Without this the claim is unfalsifiable in the direction that matters. A walk
/// that resolved nothing would fail loudly on the first modelled row, but a walk
/// that resolved anything at all would pass every filter the model happened to
/// name.
fn assert_a_filter_that_selects_nothing_refuses() {
    let tree = build_repository(&FIXTURE_FILES, false);
    let selected: BTreeSet<String> = [FIXTURE_SELECTED.to_owned()].into_iter().collect();
    let profile = selected.clone();

    for (filter, owner) in FIXTURE_ANSWERS {
        let answered = answer(tree.path(), FIXTURE_ROOT, filter, &selected, &profile)
            .unwrap_or_else(|error| panic!("the fixture answers `{filter}`, and {error}"));
        assert_eq!(
            &*answered.file, owner,
            "`{filter}` selects its declaring file"
        );
    }

    for (filter, phrase) in FIXTURE_REFUSALS {
        match answer(tree.path(), FIXTURE_ROOT, filter, &selected, &profile) {
            Ok(selection) => panic!(
                "`{filter}` selects no registered test, and the walk said {}",
                selection.file
            ),
            Err(refusal) => assert!(
                refusal.contains(phrase),
                "`{filter}` must be refused with {phrase:?}, and the walk said: {refusal}"
            ),
        }
    }
}
