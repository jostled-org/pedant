//! Real temporary Cargo projects and the guarded `pedant gate` runs over them.
//!
//! Every fixture owns one `TempDir` and nothing else: the repository, the
//! isolated configuration home, and any PATH sentinel live beneath it, and RAII
//! releases the whole tree on success, failure, and panic alike. Children run
//! under the package-shared process guard, so a row asserts only after the
//! child's whole tree is killed, reaped, and drained.
//!
//! Every repository more than one module reads is stated here once. A consumer
//! that rebuilt one of them could disagree with its peers about the corpus they
//! both claim to judge.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::process_guard::{BUDGET, Completed, Run, execute};

/// How long a killed tree may take to leave the process table.
///
/// Teardown has already signalled the group and joined both drains, so this
/// covers only the interval between a descendant's last write and its reaping
/// by whichever process adopted it.
const REAP_BUDGET: Duration = Duration::from_secs(5);

/// The manifest a single-package fixture library declares.
pub(crate) const ROOT_MANIFEST: &str =
    "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2024\"\n";

/// The sole root-target label a single-package library project reports.
pub(crate) const LIBRARY_TARGET: &str = ".#lib:demo";

/// The `left` half of the boundary-crossing pair: `up` calls into `right`.
pub(crate) const CROSSING_UP: &str = "pub fn up() { crate::right::down(); }\n";

/// The `right` half: `down` calls back into `left`, so the one cycle these two
/// sources form crosses two declared module partitions.
pub(crate) const CROSSING_DOWN: &str = "pub fn down() { crate::left::up(); }\n";

/// Every declared target of [`workspace_fixture`], in the exact order project
/// mode must report them.
pub(crate) const WORKSPACE_TARGETS: &[&str] = &[
    "alpha#lib:alpha",
    "alpha#bin:alpha",
    "alpha#build-script:build-script-build",
    "beta#lib:beta",
];

/// The two targets whose closures share `alpha`'s boundary-crossing sources.
///
/// The binary reaches them through its own package's library, so one cycle in
/// one pair of files is judged once per selected root target.
pub(crate) const SHARING_TARGETS: [&str; 2] = ["alpha#lib:alpha", "alpha#bin:alpha"];

/// One path exactly as a command-line argument spells it.
pub(crate) fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Every analyzed root-target label one project payload reports, in order.
pub(crate) fn analyzed_targets(payload: &serde_json::Value) -> Vec<&str> {
    payload["analyzed_targets"]
        .as_array()
        .expect("project mode reports analyzed_targets")
        .iter()
        .map(|value| value.as_str().expect("a target label is a string"))
        .collect()
}

/// One run's stdout, parsed as JSON.
///
/// The panic prints the whole transcript: a run that wrote nothing said why on
/// stderr, and a message holding only the empty stdout would drop it.
///
/// A free function rather than a method, because `Completed` is declared in the
/// shared process guard and both test roots hold its inherent API there.
pub(crate) fn json_payload(run: &Completed) -> serde_json::Value {
    serde_json::from_str(&run.stdout).unwrap_or_else(|error| {
        panic!(
            "gate output should parse as JSON ({error}): {}",
            run.transcript()
        )
    })
}

/// One materialized repository and the isolated environment its children run in.
pub(crate) struct ProjectFixture {
    directory: tempfile::TempDir,
}

/// Everything a guarded gate run may vary beyond its arguments.
pub(crate) struct RunOptions<'a> {
    /// Working directory the child starts in; the scratch root by default.
    pub(crate) cwd: Option<&'a Path>,
    /// Directory prepended to `PATH`, which is how a toolchain sentinel is
    /// installed.
    pub(crate) path_prefix: Option<&'a Path>,
    /// Bytes written to the child's stdin, closed immediately afterwards.
    pub(crate) stdin: Option<&'a [u8]>,
    /// Whether the parent keeps the child's stdout reader.
    pub(crate) capture_stdout: bool,
    /// Ceiling on how long the guarded child may run.
    pub(crate) budget: Duration,
}

impl Default for RunOptions<'_> {
    fn default() -> Self {
        Self {
            cwd: None,
            path_prefix: None,
            stdin: None,
            capture_stdout: true,
            budget: BUDGET,
        }
    }
}

impl ProjectFixture {
    /// Materialize `files` beneath a fresh temporary repository root.
    pub(crate) fn build(files: &[(&str, &str)]) -> Self {
        let directory = tempfile::tempdir().expect("a temporary directory should be available");
        let fixture = Self { directory };
        fs::create_dir_all(fixture.config_home())
            .expect("the isolated configuration home should be creatable");
        for (relative, contents) in files {
            fixture.write(relative, contents);
        }
        fixture
    }

    /// Write one repository-relative source, creating its parents.
    pub(crate) fn write(&self, relative: &str, contents: &str) {
        let path = self.root().join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("a fixture directory should be creatable");
        }
        fs::write(&path, contents)
            .unwrap_or_else(|error| panic!("{} should be writable: {error}", path.display()));
    }

    /// Remove one repository-relative path that a row wrote earlier.
    pub(crate) fn remove(&self, relative: &str) {
        let path = self.root().join(relative);
        fs::remove_file(&path)
            .unwrap_or_else(|error| panic!("{} should be removable: {error}", path.display()));
    }

    /// The repository root the gate is pointed at.
    pub(crate) fn root(&self) -> PathBuf {
        self.directory.path().join("repo")
    }

    /// The fixture-local scratch directory that holds everything else.
    pub(crate) fn scratch(&self) -> &Path {
        self.directory.path()
    }

    /// One repository-relative path spelled as a command-line argument.
    pub(crate) fn path_arg(&self, relative: &str) -> String {
        path_text(&self.root().join(relative))
    }

    /// One scratch-relative path spelled as a command-line argument.
    pub(crate) fn scratch_arg(&self, relative: &str) -> String {
        path_text(&self.scratch().join(relative))
    }

    /// A configuration home no developer or CI global config can reach.
    pub(crate) fn config_home(&self) -> PathBuf {
        self.directory.path().join("config-home")
    }

    /// Write the global `pedant/config.toml` beneath that isolated home.
    pub(crate) fn write_global_config(&self, contents: &str) {
        let path = self.config_home().join("pedant").join("config.toml");
        fs::create_dir_all(path.parent().expect("the global config has a parent"))
            .expect("the global config directory should be creatable");
        fs::write(&path, contents).expect("the global config should be writable");
    }

    /// Run `pedant gate` with the fixture's isolated environment.
    pub(crate) fn gate(&self, args: &[&str]) -> Completed {
        self.gate_with(args, &RunOptions::default())
    }

    /// Run `pedant gate` from inside the fixture's own repository root.
    ///
    /// Configuration discovery and relative paths both read the working
    /// directory, so a row that means "as an operator standing in the
    /// repository" says so here rather than restating the options.
    pub(crate) fn gate_in_root(&self, args: &[&str]) -> Completed {
        let root = self.root();
        self.gate_with(
            args,
            &RunOptions {
                cwd: Some(&root),
                ..RunOptions::default()
            },
        )
    }

    /// Run `pedant gate --project <root>` with any extra arguments.
    pub(crate) fn project_gate(&self, extra: &[&str]) -> Completed {
        self.project_gate_with(extra, &RunOptions::default())
    }

    /// The same project run under caller-stated run options.
    pub(crate) fn project_gate_with(&self, extra: &[&str], options: &RunOptions<'_>) -> Completed {
        let root = path_text(&self.root());
        let mut args: Vec<&str> = vec!["--project", root.as_str()];
        args.extend_from_slice(extra);
        self.gate_with(&args, options)
    }

    /// Run `pedant gate` under caller-stated run options.
    pub(crate) fn gate_with(&self, args: &[&str], options: &RunOptions<'_>) -> Completed {
        let mut full: Vec<&str> = Vec::with_capacity(args.len() + 1);
        full.push("gate");
        full.extend_from_slice(args);
        self.spawn(&full, options)
    }

    /// Run any `pedant` subcommand under the same isolated environment.
    pub(crate) fn run(&self, args: &[&str]) -> Completed {
        self.spawn(args, &RunOptions::default())
    }

    /// Run any `pedant` subcommand under caller-stated run options.
    pub(crate) fn spawn(&self, args: &[&str], options: &RunOptions<'_>) -> Completed {
        let home = path_text(&self.config_home());
        let environment = [
            ("XDG_CONFIG_HOME", home.as_str()),
            ("HOME", home.as_str()),
            ("CARGO_TERM_COLOR", "never"),
        ];
        let cwd = options
            .cwd
            .map_or_else(|| self.directory.path().to_path_buf(), Path::to_path_buf);
        let mut run = Run::new(&cwd, args);
        run.env = &environment;
        run.path_prefix = options.path_prefix;
        run.stdin = options.stdin;
        run.capture_stdout = options.capture_stdout;
        run.budget = options.budget;
        let completed =
            execute(&run).unwrap_or_else(|failure| panic!("the guarded run failed: {failure}"));
        assert_bounded_by_stated_ceiling(&completed, options);
        assert_tree_is_gone(&completed);
        completed
    }
}

/// The guard bounded the child by the ceiling its row asked for.
///
/// The line above hands `options.budget` to the run, and nothing else in this
/// root observes whether it arrived: a row that dropped that wiring would still
/// pass every assertion its journey makes, and would only be caught by a child
/// slow enough to overrun the default it silently fell back to. This reads the
/// ceiling the wait itself used, so the fallback fails here instead.
fn assert_bounded_by_stated_ceiling(completed: &Completed, options: &RunOptions<'_>) {
    assert_eq!(
        completed.budget, options.budget,
        "the guard bounded the child by the ceiling this row stated"
    );
}

/// Nothing the guarded child started outlived the guard that owned it.
///
/// Stated once here because every row in this root reaches its child through
/// [`ProjectFixture::spawn`], and because the claim is the same for all of
/// them: the gate reads a repository someone else wrote and may run a
/// toolchain over it, so a child here is a tree. Teardown kills that tree
/// before a caller may assert anything, and this is what falsifies the kill
/// having missed a member.
fn assert_tree_is_gone(completed: &Completed) {
    assert!(
        completed.tree_is_gone(REAP_BUDGET),
        "tree {} outlived its guard: {}",
        completed.tree_root(),
        completed.transcript()
    );
}

/// A single-package library whose `left` and `right` modules hold the stated
/// sources.
pub(crate) fn split_module_project(left: &str, right: &str) -> ProjectFixture {
    ProjectFixture::build(&[
        ("Cargo.toml", ROOT_MANIFEST),
        ("src/lib.rs", "pub mod left;\npub mod right;\n"),
        ("src/left.rs", left),
        ("src/right.rs", right),
    ])
}

/// The corpus most rows read: one call from `left` into `right`.
pub(crate) fn simple_project() -> ProjectFixture {
    split_module_project("pub fn item() { crate::right::a(); }\n", "pub fn a() {}\n")
}

/// The corpus one denied boundary crossing needs: a single cycle spanning the
/// two declared partitions of one library.
pub(crate) fn crossing_project() -> ProjectFixture {
    split_module_project(CROSSING_UP, CROSSING_DOWN)
}

/// One workspace whose members declare every target kind, plus a non-member
/// in-root path dependency.
///
/// `alpha` carries a boundary-crossing cycle so the corpus bears verdicts: a
/// zero-verdict workspace would prove target ordering while leaving verdict
/// ordering, and target-scoped repetition, entirely unexercised.
pub(crate) fn workspace_fixture(reversed: bool) -> ProjectFixture {
    let mut files: Vec<(&str, &str)> = vec![
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"alpha\", \"beta\"]\nresolver = \"3\"\n",
        ),
        (
            "alpha/Cargo.toml",
            "[package]\nname = \"alpha\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\nhelper = { path = \"../vendor/helper\" }\n",
        ),
        ("alpha/src/lib.rs", "pub mod left;\npub mod right;\n"),
        ("alpha/src/left.rs", CROSSING_UP),
        ("alpha/src/right.rs", CROSSING_DOWN),
        ("alpha/src/main.rs", "fn main() {}\n"),
        ("alpha/build.rs", "fn main() {}\n"),
        ("alpha/examples/demo.rs", "fn main() {}\n"),
        ("alpha/tests/it.rs", "#[test]\nfn t() {}\n"),
        ("alpha/benches/b.rs", "fn main() {}\n"),
        (
            "beta/Cargo.toml",
            "[package]\nname = \"beta\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        ),
        ("beta/src/lib.rs", "pub fn b() {}\n"),
        (
            "vendor/helper/Cargo.toml",
            "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        ),
        ("vendor/helper/src/lib.rs", "pub fn helper_fn() {}\n"),
    ];
    if reversed {
        files.reverse();
    }
    ProjectFixture::build(&files)
}

/// A whole `[gate.module-boundary]` configuration body.
pub(crate) fn boundary_config(body: &str) -> String {
    format!("[gate.module-boundary]\n{body}\n")
}

/// The same section with exactly one field set.
pub(crate) fn boundary_field(field: &str, value: &str) -> String {
    boundary_config(&format!("{field} = {value}"))
}

/// Sentinel executables that record that they ran and then fail.
///
/// Tier 1 must invoke no toolchain, so a marker written by any of these is the
/// proof that it did. Windows resolves a bare `cargo` through `PATHEXT`, so the
/// sentinels are `.cmd` scripts there and need no permission bit; a Unix shell
/// script needs one, and nothing else differs.
pub(crate) fn install_toolchain_sentinels(directory: &Path, marker: &Path) {
    fs::create_dir_all(directory).expect("the sentinel directory should be creatable");
    for name in ["cargo", "rustc", "rust-analyzer"] {
        let path = directory.join(format!("{name}{SENTINEL_EXTENSION}"));
        fs::write(&path, sentinel_source(name, marker)).expect("the sentinel should be writable");
        #[cfg(unix)]
        make_runnable(&path);
    }
}

/// The suffix a sentinel file name needs to be found on this platform.
#[cfg(unix)]
const SENTINEL_EXTENSION: &str = "";

#[cfg(windows)]
const SENTINEL_EXTENSION: &str = ".cmd";

#[cfg(unix)]
fn sentinel_source(name: &str, marker: &Path) -> String {
    format!(
        "#!/bin/sh\necho \"{name}\" >> \"{}\"\nexit 3\n",
        marker.display()
    )
}

#[cfg(windows)]
fn sentinel_source(name: &str, marker: &Path) -> String {
    format!(
        "@echo off\r\n>>\"{}\" echo {name}\r\nexit /b 3\r\n",
        marker.display()
    )
}

#[cfg(unix)]
fn make_runnable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .expect("the sentinel should be executable");
}
