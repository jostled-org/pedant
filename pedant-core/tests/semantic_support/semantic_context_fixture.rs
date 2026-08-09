//! Shared and fresh semantic contexts used by the integration cases.

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use pedant_core::SemanticContext;

use crate::fixtures::{dataflow_workspace_root, fixture_workspace_root};
use crate::workspace_load::{load, recovered_lock};

static FIXTURE_CONTEXT: Mutex<Option<SemanticContext>> = Mutex::new(None);

pub(crate) struct TestSemanticContext(TestSemanticContextInner);

enum TestSemanticContextInner {
    Shared {
        context: MutexGuard<'static, Option<SemanticContext>>,
    },
    Fresh(Box<SemanticContext>),
}

impl Deref for TestSemanticContext {
    type Target = SemanticContext;

    fn deref(&self) -> &Self::Target {
        match &self.0 {
            TestSemanticContextInner::Shared { context } => context
                .as_ref()
                .expect("shared semantic fixture context should be initialized"),
            TestSemanticContextInner::Fresh(context) => context,
        }
    }
}

pub(crate) fn load_semantic_context(root: &Path) -> Option<TestSemanticContext> {
    match is_fixture_workspace(root) {
        true => load_shared_semantic_context(),
        false => load_fresh_semantic_context(root),
    }
}

pub(crate) fn load_fresh_semantic_context(root: &Path) -> Option<TestSemanticContext> {
    load(root)
        .map(Box::new)
        .map(TestSemanticContextInner::Fresh)
        .map(TestSemanticContext)
}

fn load_shared_semantic_context() -> Option<TestSemanticContext> {
    let mut context = recovered_lock(&FIXTURE_CONTEXT);
    if context.is_none() {
        *context = load(&fixture_suite_workspace_root());
    }
    context.as_ref()?;
    Some(TestSemanticContext(TestSemanticContextInner::Shared {
        context,
    }))
}

fn is_fixture_workspace(root: &Path) -> bool {
    matches!(
        (
            root == fixture_workspace_root(),
            root == dataflow_workspace_root(),
        ),
        (true, false) | (false, true)
    )
}

fn fixture_suite_workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("semantic_suite")
}
