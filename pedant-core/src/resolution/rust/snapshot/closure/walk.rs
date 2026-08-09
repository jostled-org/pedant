//! Traversal of one target's module declarations into frames.

use std::path::PathBuf;
use std::sync::Arc;

use super::super::declaration::ModuleDeclaration;
use super::super::error::{ClosureSite, ResolutionLimit, SourceClosureFailure};
use super::super::failure::limit_failure;
use super::super::module::{RustModuleId, RustModuleInstance};
use super::super::store::SourceStore;
use super::entry::ClosureEntry;
use super::path::{candidate_paths, child_directory, file_directory, inline_directories};
use super::state::{UnitClosure, Walk};
use crate::resolution::rust::edition::CargoEdition;

/// One module instance that still owes its children.
pub(super) struct Frame {
    pub(super) module: RustModuleId,
    pub(super) source: Arc<str>,
    pub(super) directory: PathBuf,
    pub(super) declared_directory: PathBuf,
    declarations: Arc<[ModuleDeclaration]>,
    depth: u32,
    edition: CargoEdition,
}

/// One child declaration under resolution.
pub(super) struct ChildContext<'a> {
    pub(super) frame: &'a Frame,
    pub(super) declaration: &'a ModuleDeclaration,
    depth: u32,
}

/// Walk one target's module closure into the shared store.
///
/// Returns `None` when the entry point itself could not be reached; any other
/// failure is recorded and leaves the caller to refuse the whole snapshot.
pub(in crate::resolution::rust::snapshot) fn walk_unit(
    store: &mut SourceStore,
    entry: &ClosureEntry<'_>,
    failures: &mut Vec<SourceClosureFailure>,
) -> Option<UnitClosure> {
    let site = ClosureSite::Target {
        name: Box::from(entry.target_name),
        entry: Box::from(entry.entry_path),
    };
    let absolute = store.root().join(entry.entry_path);
    let canonical = collect(store.canonical_inside(&absolute, &site), failures)?;
    let path = collect(store.intern(&canonical, &site, entry.edition), failures)?;
    let declarations = collect(store.declarations((&*path, 0), &site), failures)?;

    let mut walk = Walk::rooted(&path, store.limits().max_module_instances);
    let mut pending = vec![Frame {
        module: walk.root_id(),
        source: Arc::clone(&path),
        directory: child_directory(&canonical, true),
        declared_directory: file_directory(&canonical),
        declarations,
        depth: 0,
        edition: entry.edition,
    }];
    while let Some(frame) = pending.pop() {
        if !expand(store, &frame, (&mut walk, &mut pending), failures) {
            break;
        }
    }
    Some(walk.finish())
}

fn collect<T>(
    outcome: Result<T, SourceClosureFailure>,
    failures: &mut Vec<SourceClosureFailure>,
) -> Option<T> {
    match outcome {
        Ok(value) => Some(value),
        Err(failure) => {
            failures.push(failure);
            None
        }
    }
}

fn expand(
    store: &mut SourceStore,
    frame: &Frame,
    walk: (&mut Walk, &mut Vec<Frame>),
    failures: &mut Vec<SourceClosureFailure>,
) -> bool {
    let (instances, pending) = walk;
    for declaration in frame.declarations.iter() {
        let context = ChildContext {
            frame,
            declaration,
            depth: frame.depth.saturating_add(1),
        };
        let outcome = resolve(store, &context, instances);
        if !queue(outcome, pending, failures) {
            return false;
        }
    }
    true
}

fn queue(
    outcome: Result<Vec<Frame>, SourceClosureFailure>,
    pending: &mut Vec<Frame>,
    failures: &mut Vec<SourceClosureFailure>,
) -> bool {
    match outcome {
        Ok(next) => {
            pending.extend(next);
            true
        }
        Err(failure) => {
            let fatal = failure.is_fatal();
            failures.push(failure);
            !fatal
        }
    }
}

fn resolve(
    store: &mut SourceStore,
    context: &ChildContext<'_>,
    walk: &mut Walk,
) -> Result<Vec<Frame>, SourceClosureFailure> {
    check_depth(store, context)?;
    match context.declaration.inline_scope {
        Some(scope) => inline_frames(store, context, (scope, walk)),
        None => external_frames(store, context, walk),
    }
}

fn check_depth(
    store: &SourceStore,
    context: &ChildContext<'_>,
) -> Result<(), SourceClosureFailure> {
    let ceiling = store.limits().max_module_depth;
    match context.depth > ceiling {
        true => Err(limit_failure(
            ResolutionLimit::ModuleDepth,
            (
                &module_site(context),
                Some(Box::from(&*context.frame.source)),
            ),
            ceiling.into(),
        )),
        false => Ok(()),
    }
}

fn check_instances(walk: &Walk, context: &ChildContext<'_>) -> Result<(), SourceClosureFailure> {
    match walk.at_capacity() {
        true => Err(limit_failure(
            ResolutionLimit::ModuleInstances,
            (
                &module_site(context),
                Some(Box::from(&*context.frame.source)),
            ),
            walk.ceiling().into(),
        )),
        false => Ok(()),
    }
}

fn inline_frames(
    store: &SourceStore,
    context: &ChildContext<'_>,
    inline: (u32, &mut Walk),
) -> Result<Vec<Frame>, SourceClosureFailure> {
    let (scope, walk) = inline;
    let children = store.declarations((&*context.frame.source, scope), &module_site(context))?;
    let mut frames = Vec::new();
    for directory in inline_directories(context).into_vec() {
        frames.push(inline_frame(
            context,
            (scope, Arc::clone(&children), directory),
            walk,
        )?);
    }
    Ok(frames)
}

fn inline_frame(
    context: &ChildContext<'_>,
    inline: (u32, Arc<[ModuleDeclaration]>, PathBuf),
    walk: &mut Walk,
) -> Result<Frame, SourceClosureFailure> {
    let (scope, children, directory) = inline;
    check_instances(walk, context)?;
    let module = walk.push(RustModuleInstance {
        id: walk.next_id(),
        parent: Some(context.frame.module),
        name: Arc::clone(&context.declaration.name),
        path: Arc::clone(&context.frame.source),
        inline: true,
        depth: context.depth,
        scope,
        declaration: Some(context.declaration.index),
    });
    Ok(Frame {
        module,
        source: Arc::clone(&context.frame.source),
        declared_directory: directory.clone(),
        directory,
        declarations: children,
        depth: context.depth,
        edition: context.frame.edition,
    })
}

fn external_frames(
    store: &mut SourceStore,
    context: &ChildContext<'_>,
    walk: &mut Walk,
) -> Result<Vec<Frame>, SourceClosureFailure> {
    let site = module_site(context);
    let mut frames = Vec::new();
    for candidate in candidate_paths(store, context, &site)?.into_vec() {
        frames.extend(external_frame(store, context, (&candidate, &site), walk)?);
    }
    Ok(frames)
}

fn external_frame(
    store: &mut SourceStore,
    context: &ChildContext<'_>,
    candidate: (&std::path::Path, &ClosureSite),
    walk: &mut Walk,
) -> Result<Option<Frame>, SourceClosureFailure> {
    let (candidate, site) = candidate;
    let canonical = store.canonical_inside(candidate, site)?;
    let path = store.intern(&canonical, site, context.frame.edition)?;
    check_instances(walk, context)?;
    let module = walk.push(RustModuleInstance {
        id: walk.next_id(),
        parent: Some(context.frame.module),
        name: Arc::clone(&context.declaration.name),
        path: Arc::clone(&path),
        inline: false,
        depth: context.depth,
        scope: 0,
        declaration: Some(context.declaration.index),
    });
    walk.record_source(&path);
    match walk.ancestor_holds(context.frame.module, &path) {
        true => Ok(None),
        false => Ok(Some(Frame {
            module,
            declarations: store.declarations((&*path, 0), site)?,
            source: path,
            directory: child_directory(&canonical, false),
            declared_directory: file_directory(&canonical),
            depth: context.depth,
            edition: context.frame.edition,
        })),
    }
}

fn module_site(context: &ChildContext<'_>) -> ClosureSite {
    ClosureSite::Module {
        file: Box::from(&*context.frame.source),
        module: Box::from(&*context.declaration.name),
    }
}
