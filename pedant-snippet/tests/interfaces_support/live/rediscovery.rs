//! An authority or an ignore file changes what the corpus is, not just what one
//! member of it holds.

use pedant_snippet::{ChangeKind, TransactionOutcome};

use super::harness::{Live, admits, batch_rows, declared_names, project_keys, source_paths};

/// A second Cargo member, added while the index is live.
const MEMBER: (&str, &str) = (
    "crate-b/Cargo.toml",
    "[package]\nname = \"crate-b\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
);

/// Its one source.
const MEMBER_SOURCE: (&str, &str) = ("crate-b/src/lib.rs", "pub fn second() -> u32 {\n    9\n}\n");

/// A TypeScript source, placed while the index is live.
const TYPESCRIPT: (&str, &str) = (
    "web/app.ts",
    "export function widen(count: number): number {\n  return count + 1;\n}\n",
);

/// A JavaScript one beside it.
const JAVASCRIPT: (&str, &str) = (
    "web/app.js",
    "export function narrow(count) {\n  return count - 1;\n}\n",
);

/// The config files that sit beside them and decide nothing about the corpus.
const WEB_CONFIGS: &[(&str, &str)] = &[
    ("web/tsconfig.json", "{\n  \"compilerOptions\": {}\n}\n"),
    ("web/jsconfig.json", "{\n  \"compilerOptions\": {}\n}\n"),
];

/// A changed authority, ignore file, or new source rediscovers the corpus; a
/// change this index answers for nothing is discarded before any of it.
#[test]
fn live_index_rediscovers_authority_and_ignore_changes() {
    an_ignore_file_decides_which_sources_are_loose();
    an_ignored_source_reaches_no_batch_until_the_rules_release_it();
    an_authority_decides_which_projects_exist();
    a_typescript_and_javascript_source_are_indexed_and_own_no_project();
    only_authorities_ignore_files_and_sources_reach_a_batch();
}

/// A write to an ignored source states no batch row, and the same write states
/// one again once the ignore file stops excluding it.
///
/// The two halves are one claim and neither holds alone. Without the first, a
/// generator writing into an ignored tree rebuilds the whole repository for an
/// index that comes back byte-identical — twice a second, for as long as it
/// runs. Without the second, the rules a batch is keyed against are a snapshot
/// taken when the index opened, and a repository that stopped ignoring a tree
/// would have a live index that never followed that tree again: quieter than
/// the storm, and far worse.
fn an_ignored_source_reaches_no_batch_until_the_rules_release_it() {
    let live = Live::opened();

    live.tree().place(".gitignore", "scripts/\n");
    live.apply(&[(".gitignore", ChangeKind::Created)]);

    let ignored = live.batch(&[("scripts/tool.py", ChangeKind::Modified)]);
    assert!(
        ignored.is_empty(),
        "a source the repository's own ignore rules exclude is one the corpus walk would \
         reach the same conclusion about, so it costs no rebuild: {:?}",
        batch_rows(&ignored)
    );

    live.tree().write(".gitignore", "nothing-here/\n");
    live.apply(&[(".gitignore", ChangeKind::Modified)]);

    let released = live.batch(&[("scripts/tool.py", ChangeKind::Modified)]);
    assert_eq!(
        &*batch_rows(&released),
        ["source|scripts/tool.py|modified"],
        "and the rules a later batch is keyed against are the ones the repository now states"
    );
}

/// Creating, changing, and deleting an ignore file each rediscovers the corpus.
fn an_ignore_file_decides_which_sources_are_loose() {
    let live = Live::opened();
    live.tree()
        .place("scripts/extra.py", "def extra():\n    return 2\n");
    live.apply(&[("scripts/extra.py", ChangeKind::Created)]);
    assert!(
        admits(&live.state(), "scripts/extra.py"),
        "a new recognized source is admitted"
    );

    live.tree().place(".gitignore", "scripts/\n");
    let created = live.apply(&[(".gitignore", ChangeKind::Created)]);
    assert_eq!(
        &*batch_rows(created.batch()),
        ["ignore|.gitignore|created"],
        "an ignore file is an ignore row, not a source one"
    );
    // The corpus that survives, rather than the prefix that does not: an
    // exclusion stated as an absence holds just as well over a rediscovery that
    // admitted nothing at all.
    assert_eq!(
        &*source_paths(&live.state()),
        ["crate-a/src/lib.rs", "main.go"],
        "and the two sources it excludes are the only two it excludes"
    );

    live.tree().write(".gitignore", "nothing-here/\n");
    live.apply(&[(".gitignore", ChangeKind::Modified)]);
    assert!(
        admits(&live.state(), "scripts/extra.py"),
        "a changed ignore file rediscovers the corpus rather than the file it names"
    );

    // Excluding again first, so the removal below has something to undo. A
    // deletion tested against an ignore file that already excluded nothing is a
    // claim an apply that did nothing would satisfy.
    live.tree().write(".gitignore", "scripts/\n");
    live.apply(&[(".gitignore", ChangeKind::Modified)]);
    assert!(
        !admits(&live.state(), "scripts/tool.py"),
        "a restored ignore file excludes the directory it names again"
    );

    live.tree().remove(".gitignore");
    let removed = live.apply(&[(".gitignore", ChangeKind::Removed)]);
    assert_eq!(
        &*batch_rows(removed.batch()),
        ["ignore|.gitignore|removed"],
        "a deleted ignore file is an ignore row too"
    );
    assert_eq!(
        removed.outcome(),
        TransactionOutcome::Published,
        "and one this repository rebuilds over"
    );
    assert!(
        admits(&live.state(), "scripts/tool.py"),
        "which leaves every source loose again"
    );
}

/// The two projects the live fixture's own authorities select.
///
/// Asserted wherever a later comparison is made against a project list, so that
/// comparison is between lists known to hold something: two lists derived from
/// the subject's own answers are equal when the subject stopped answering at
/// all.
fn assert_fixture_projects(keys: &[String], subject: &str) {
    assert!(
        keys.iter().any(|key| key.contains("crate-a")),
        "{subject}: the workspace member is a project: {keys:?}"
    );
    assert!(
        keys.iter().any(|key| key.contains("go.mod")),
        "{subject}: and so is the Go module: {keys:?}"
    );
}

/// Adding and deleting a manifest adds and deletes the project slices it
/// selects.
fn an_authority_decides_which_projects_exist() {
    let mut live = Live::watching();
    let before = project_keys(&live.state());
    assert_fixture_projects(&before, "before anything changes");

    live.tree().place(MEMBER_SOURCE.0, MEMBER_SOURCE.1);
    live.tree().place(MEMBER.0, MEMBER.1);
    live.tree().write(
        "Cargo.toml",
        "[workspace]\nmembers = [\"crate-a\", \"crate-b\"]\nresolver = \"3\"\n",
    );

    let widened = live.wait_for("the new member becomes a project", |state| {
        let keys = project_keys(state);
        keys.iter()
            .any(|key| key.contains("crate-b"))
            .then_some(keys)
    });
    assert!(
        admits(&live.state(), MEMBER_SOURCE.0),
        "and its source is admitted: {widened:?}"
    );

    live.tree().remove("go.mod");
    let narrowed = live.wait_for("the deleted module stops being a project", |state| {
        let keys = project_keys(state);
        (!keys.iter().any(|key| key.contains("go.mod"))).then_some(keys)
    });
    assert!(
        admits(&live.state(), "main.go"),
        "its source is still a recognized file, now loose rather than in a project: {narrowed:?}"
    );

    live.stop().expect("the applying thread ends cleanly");
}

/// A live ECMAScript source is indexed; the config beside it decides nothing.
///
/// Both halves of the claim need the tree rather than the batch. That a
/// `tsconfig.json` is not an authority is visible in a batch row, but that a
/// `.ts` file is a *source* is only visible once one exists: a row saying
/// `source|web/app.ts|created` is a classification of a string, and a string
/// classifies the same whether or not the walk that follows admits the file.
fn a_typescript_and_javascript_source_are_indexed_and_own_no_project() {
    let live = Live::opened();
    let projects = project_keys(&live.state());
    assert_fixture_projects(&projects, "the projects the config files must not disturb");

    for (path, contents) in [TYPESCRIPT, JAVASCRIPT] {
        live.tree().place(path, contents);
    }
    for (path, contents) in WEB_CONFIGS {
        live.tree().place(path, contents);
    }
    live.apply(&[
        (TYPESCRIPT.0, ChangeKind::Created),
        (JAVASCRIPT.0, ChangeKind::Created),
    ]);

    let after = live.state();
    let admitted = source_paths(&after);
    for (path, _) in [TYPESCRIPT, JAVASCRIPT] {
        assert!(
            admits(&after, path),
            "{path} is a source this index admits: {admitted:?}"
        );
    }
    assert_eq!(
        &*declared_names(&after, TYPESCRIPT.0),
        ["widen"],
        "and the TypeScript source states the structure its own bytes declare"
    );
    assert_eq!(
        &*declared_names(&after, JAVASCRIPT.0),
        ["narrow"],
        "as does the JavaScript one beside it"
    );
    assert_eq!(
        project_keys(&after),
        projects,
        "while the config files beside them select no project: neither language has an \
         authority in this design, so both sources are loose"
    );
}

/// Only the three roles reach a batch, and everything else is discarded.
fn only_authorities_ignore_files_and_sources_reach_a_batch() {
    let live = Live::opened();

    let admitted = live.batch(&[
        ("crate-a/Cargo.toml", ChangeKind::Modified),
        (".gitignore", ChangeKind::Created),
        ("web/app.ts", ChangeKind::Created),
        ("web/app.js", ChangeKind::Created),
        ("go.mod", ChangeKind::Modified),
    ]);
    assert_eq!(
        &*batch_rows(&admitted),
        [
            "authority|crate-a/Cargo.toml|modified",
            "authority|go.mod|modified",
            "ignore|.gitignore|created",
            "source|web/app.js|created",
            "source|web/app.ts|created",
        ],
        "an authority precedes an ignore file, which precedes a source"
    );

    let discarded = live.batch(&[
        ("web/tsconfig.json", ChangeKind::Created),
        ("web/jsconfig.json", ChangeKind::Modified),
        ("README.md", ChangeKind::Created),
        ("target/debug/generated.rs", ChangeKind::Created),
        ("node_modules/pkg/index.js", ChangeKind::Created),
        (".git/HEAD", ChangeKind::Modified),
    ]);
    assert!(
        discarded.is_empty(),
        "a TypeScript or JavaScript config is not an authority in this design, an unrecognized \
         file is not a source, and an excluded directory is entered by nothing: {:?}",
        batch_rows(&discarded)
    );

    let outside = live.reported(&[pedant_snippet::ObservedChange::new(
        live.tree().root().join("..").join("outside.rs"),
        ChangeKind::Created,
    )]);
    assert!(
        outside.is_empty(),
        "and a path that is not beneath this root is not this repository's: {:?}",
        batch_rows(&outside)
    );
}
