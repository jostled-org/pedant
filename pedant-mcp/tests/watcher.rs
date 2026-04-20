use std::fs;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use pedant_core::Config;
use pedant_mcp::index::WorkspaceIndex;
use pedant_mcp::watcher::start_watcher;
use pedant_types::Capability;

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn copy_fixture_to_temp(name: &str) -> tempfile::TempDir {
    let src = fixture_path(name);
    let tmp = tempfile::tempdir().expect("failed to create temp dir");
    copy_dir_recursive(&src, tmp.path()).expect("failed to copy fixture");
    tmp
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let target = dst.join(entry.file_name());
        match entry.file_type()?.is_dir() {
            true => {
                fs::create_dir_all(&target)?;
                copy_dir_recursive(&entry.path(), &target)?;
            }
            false => {
                fs::copy(entry.path(), &target)?;
            }
        }
    }
    Ok(())
}

fn wait_for_degraded_file(index: &Arc<RwLock<WorkspaceIndex>>) {
    let started_at = Instant::now();

    loop {
        let degraded_present = index
            .read()
            .expect("index lock poisoned")
            .crate_degraded_files("lib-a")
            .is_some_and(|mut files| files.any(|(path, _)| path.ends_with("other.rs")));
        if degraded_present {
            return;
        }

        assert!(
            started_at.elapsed() < Duration::from_secs(5),
            "watcher did not report degraded file state after reindex failure"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_rename_reindex(index: &Arc<RwLock<WorkspaceIndex>>, old_path: &Path, new_path: &Path) {
    let started_at = Instant::now();
    let old_key = old_path.to_string_lossy();
    let new_key = new_path.to_string_lossy();

    loop {
        let renamed = {
            let guard = index.read().expect("index lock poisoned");
            guard.file_result(old_key.as_ref()).is_none()
                && guard.file_result(new_key.as_ref()).is_some()
        };
        if renamed {
            return;
        }

        assert!(
            started_at.elapsed() < Duration::from_secs(5),
            "watcher did not refresh cache after rename"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn test_watcher_keeps_last_good_result_and_marks_file_degraded() {
    let tmp = copy_fixture_to_temp("multi_crate");
    let workspace_root = tmp.path().canonicalize().unwrap();
    let config = Arc::new(Config::default());
    let index = WorkspaceIndex::build(&workspace_root, config.as_ref(), None).unwrap();
    let shared_index = Arc::new(RwLock::new(index));

    assert!(
        shared_index
            .read()
            .unwrap()
            .crate_profile("lib-a")
            .is_some_and(|profile| profile.capabilities().contains(&Capability::FileRead)),
        "expected FileRead before introducing invalid Rust"
    );

    let _watcher = start_watcher(&shared_index, Arc::clone(&config)).unwrap();
    thread::sleep(Duration::from_millis(200));

    let other_rs = workspace_root.join("lib-a/src/other.rs");
    fs::write(&other_rs, "pub fn broken( {\n").unwrap();

    wait_for_degraded_file(&shared_index);

    assert!(
        shared_index
            .read()
            .unwrap()
            .crate_profile("lib-a")
            .is_some_and(|profile| profile.capabilities().contains(&Capability::FileRead)),
        "expected FileRead to remain from the last good analysis result"
    );
}

#[test]
fn test_watcher_removes_stale_entry_after_rename() {
    let tmp = copy_fixture_to_temp("multi_crate");
    let workspace_root = tmp.path().canonicalize().unwrap();
    let config = Arc::new(Config::default());
    let index = WorkspaceIndex::build(&workspace_root, config.as_ref(), None).unwrap();
    let shared_index = Arc::new(RwLock::new(index));

    let old_path = workspace_root.join("lib-a/src/other.rs");
    let new_path = workspace_root.join("lib-a/src/renamed.rs");

    assert!(
        shared_index
            .read()
            .unwrap()
            .file_result(old_path.to_string_lossy().as_ref())
            .is_some(),
        "expected old file path to be indexed before rename"
    );

    let _watcher = start_watcher(&shared_index, Arc::clone(&config)).unwrap();
    thread::sleep(Duration::from_millis(200));

    fs::rename(&old_path, &new_path).unwrap();

    wait_for_rename_reindex(&shared_index, &old_path, &new_path);
}
