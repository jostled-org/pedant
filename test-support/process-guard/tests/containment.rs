use pedant_process_guard::run_fixture;

/// The reusable child role is harmless in an ordinary test run.
#[test]
fn process_tree_fixture() {
    run_fixture().expect("the process-tree fixture role completes");
}

#[cfg(unix)]
mod unix {
    use std::process::Command;

    use pedant_process_guard::{
        ChildContainment, ContainedProcessTree, configure_child, tree_is_live,
    };

    #[test]
    fn configured_child_that_exits_before_adoption_is_an_empty_tree() {
        let mut command = Command::new("true");
        configure_child(&mut command);
        let mut child = command.spawn().expect("the configured child starts");
        let pid = child.id();
        child.wait().expect("the short-lived child is reaped");

        let tree = ContainedProcessTree::adopting(ChildContainment::from_pid(pid))
            .expect("an already-empty configured group is adoptable");

        assert!(!tree_is_live(&tree));
    }
}

#[cfg(windows)]
mod windows {
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use pedant_process_guard::{
        ContainmentError, FIXTURE_OUTCOME_ENV, FIXTURE_PID_FILE_ENV, FIXTURE_RELEASE_FILE_ENV,
        FIXTURE_ROLE_ENV, FIXTURE_TEST_ENV, adopt_child, configure_child, descendant_pid,
        wait_until_gone,
    };

    const BUDGET: Duration = Duration::from_secs(5);
    static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    /// A configured child executes no code before adoption, then proceeds.
    #[test]
    fn child_is_suspended_until_job_assignment() {
        let fixture = Fixture::new();
        std::fs::write(&fixture.release, b"adopt").expect("the release marker is written");
        let mut command = fixture.command();
        configure_child(&mut command);
        let mut child = command.spawn().expect("the suspended child starts");

        std::thread::sleep(Duration::from_millis(200));
        assert!(
            !fixture.pid.is_file(),
            "the child cannot start its descendant before Job assignment"
        );

        let tree = adopt_child(&mut child).expect("the suspended child is adopted and resumed");
        let descendant = descendant_pid(&fixture.pid, BUDGET)
            .expect("the resumed child starts its contained descendant");
        tree.terminate().expect("the Job Object terminates");
        child.wait().expect("the direct child is reaped");
        assert!(wait_until_gone(descendant, BUDGET));
    }

    /// Omission of suspended creation is detected and the child is reaped.
    #[test]
    fn unconfigured_child_is_refused_and_reaped() {
        let fixture = Fixture::new();
        let mut child = fixture
            .command()
            .spawn()
            .expect("the unconfigured control child starts");
        let pid = child.id();
        let refusal = match adopt_child(&mut child) {
            Ok(tree) => {
                drop(tree);
                panic!("an unsuspended child was adopted")
            }
            Err(refusal) => refusal,
        };
        assert!(matches!(
            refusal,
            ContainmentError::UnexpectedThreadSuspendCount { count: 0, .. }
        ));
        assert!(
            child
                .try_wait()
                .expect("the child status is readable")
                .is_some()
        );
        assert!(wait_until_gone(pid, BUDGET));
    }

    struct Fixture {
        root: PathBuf,
        release: PathBuf,
        pid: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("pedant-process-guard-{}-{id}", std::process::id()));
            std::fs::create_dir(&root).expect("the unique fixture root is created");
            Self {
                release: root.join("release"),
                pid: root.join("descendant.pid"),
                root,
            }
        }

        fn command(&self) -> Command {
            let mut command = Command::new(std::env::current_exe().expect("test executable"));
            command
                .args(["--exact", "process_tree_fixture", "--nocapture"])
                .env(FIXTURE_ROLE_ENV, "parent")
                .env(FIXTURE_TEST_ENV, "process_tree_fixture")
                .env(FIXTURE_PID_FILE_ENV, &self.pid)
                .env(FIXTURE_RELEASE_FILE_ENV, &self.release)
                .env(FIXTURE_OUTCOME_ENV, "timeout")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            command
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::mem::drop(std::fs::remove_dir_all(&self.root));
        }
    }
}
