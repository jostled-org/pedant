//! Traversal of one target's module declarations into frames.

use std::path::Path;
use std::sync::Arc;

use super::super::declaration::ModuleDeclaration;
use super::super::error::{ClosureSite, ResolutionLimit, SourceClosureFailure};
use super::super::failure::limit_failure;
use super::super::module::{RustModuleId, RustModuleInstance};
use super::super::store::SourceStore;
use super::entry::ClosureEntry;
use super::path::{
    candidate_paths, child_directory, external_child_directory, file_directory, inline_directories,
};
use super::state::{UnitWalk, Walk};
use crate::resolution::rust::edition::CargoEdition;
use crate::resolution::rust::fault::RustSourceFault;
use crate::resolution::rust::inventory::RustFileInventory;
use crate::resolution::supply::SourceSupply;

/// One module instance that still owes its children.
///
/// Both directories are shared because frames never mutate them.
pub(super) struct Frame {
    pub(super) module: RustModuleId,
    pub(super) source: Arc<str>,
    pub(super) directory: Arc<Path>,
    pub(super) declared_directory: Arc<Path>,
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

/// Whether the traversal goes on after one resolved declaration.
///
/// Named rather than a `bool`, because both readings of a bare flag are
/// plausible here — "this branch resolved" and "keep walking" — and only one of
/// them is what the value carries.
enum Traversal {
    /// Take the next frame off the pending stack.
    Continue,
    /// A crossed ceiling makes every later step meaningless; stop.
    Halt,
}

/// The crate-root instance one unit's walk starts from.
struct Rooted {
    walk: Walk,
    pending: Vec<Frame>,
}

/// Walk one target's module closure into the shared store.
///
/// Reports how the walk ended rather than only what it reached. A crossed
/// ceiling is decided here, on the failure this walk collected, so the caller
/// that stops selecting units reads that decision instead of rescanning the
/// failures for it.
pub(in crate::resolution::rust::snapshot) fn walk_unit<
    P: SourceSupply<RustFileInventory, RustSourceFault>,
>(
    store: &mut SourceStore,
    provider: &mut P,
    entry: &ClosureEntry<'_>,
    failures: &mut Vec<SourceClosureFailure>,
) -> UnitWalk {
    let site = ClosureSite::Target {
        name: Box::from(entry.target_name),
        entry: Box::from(entry.entry_path),
    };
    match rooted(store, provider, entry, &site) {
        Ok(rooted) => follow_from(store, provider, rooted, failures),
        Err(failure) => unreached(failure, failures),
    }
}

/// The crate-root frame this unit's walk starts from, or the failure that
/// stopped the entry point itself.
fn rooted<P: SourceSupply<RustFileInventory, RustSourceFault>>(
    store: &mut SourceStore,
    provider: &mut P,
    entry: &ClosureEntry<'_>,
    site: &ClosureSite,
) -> Result<Rooted, SourceClosureFailure> {
    let absolute = store.root().join(entry.entry_path);
    let canonical = store.canonical_inside(&absolute, site)?;
    let path = store.intern(provider, &canonical, site, entry.edition)?;
    let declarations = store.declarations((&*path, 0), site)?;
    let walk = Walk::rooted(&path, store.limits().max_module_instances);
    let declared: Arc<Path> = Arc::from(file_directory(&canonical));
    let pending = vec![Frame {
        module: walk.root_id(),
        source: path,
        directory: child_directory(&canonical, &declared, true),
        declared_directory: declared,
        declarations,
        depth: 0,
        edition: entry.edition,
    }];
    Ok(Rooted { walk, pending })
}

/// Follow every pending frame, then name how the walk ended.
fn follow_from<P: SourceSupply<RustFileInventory, RustSourceFault>>(
    store: &mut SourceStore,
    provider: &mut P,
    rooted: Rooted,
    failures: &mut Vec<SourceClosureFailure>,
) -> UnitWalk {
    let Rooted {
        mut walk,
        mut pending,
    } = rooted;
    match follow(store, provider, (&mut walk, &mut pending), failures) {
        Traversal::Continue => UnitWalk::Followed(walk.finish()),
        Traversal::Halt => UnitWalk::Halted(walk.finish()),
    }
}

/// Take frames off the pending stack until it empties or a ceiling ends it.
fn follow<P: SourceSupply<RustFileInventory, RustSourceFault>>(
    store: &mut SourceStore,
    provider: &mut P,
    walk: (&mut Walk, &mut Vec<Frame>),
    failures: &mut Vec<SourceClosureFailure>,
) -> Traversal {
    let (instances, pending) = walk;
    while let Some(frame) = pending.pop() {
        match expand(store, provider, &frame, (instances, pending), failures) {
            Traversal::Continue => (),
            Traversal::Halt => return Traversal::Halt,
        }
    }
    Traversal::Continue
}

/// The entry point could not be reached, in the two ways that ends a selection.
fn unreached(failure: SourceClosureFailure, failures: &mut Vec<SourceClosureFailure>) -> UnitWalk {
    match collect(failure, failures) {
        Traversal::Halt => UnitWalk::Exhausted,
        Traversal::Continue => UnitWalk::Unreached,
    }
}

/// Record one failure and answer whether the traversal survives it.
///
/// The one owner of that decision. A crossed ceiling makes every later step
/// meaningless, so reporting the same limit once per remaining source would
/// bury the one real cause.
fn collect(failure: SourceClosureFailure, failures: &mut Vec<SourceClosureFailure>) -> Traversal {
    let fatal = failure.is_fatal();
    failures.push(failure);
    match fatal {
        true => Traversal::Halt,
        false => Traversal::Continue,
    }
}

fn expand<P: SourceSupply<RustFileInventory, RustSourceFault>>(
    store: &mut SourceStore,
    provider: &mut P,
    frame: &Frame,
    walk: (&mut Walk, &mut Vec<Frame>),
    failures: &mut Vec<SourceClosureFailure>,
) -> Traversal {
    let (instances, pending) = walk;
    for declaration in frame.declarations.iter() {
        let context = ChildContext {
            frame,
            declaration,
            depth: frame.depth.saturating_add(1),
        };
        let outcome = resolve(store, provider, &context, instances);
        match queue(outcome, pending, failures) {
            Traversal::Continue => (),
            Traversal::Halt => return Traversal::Halt,
        }
    }
    Traversal::Continue
}

fn queue(
    outcome: Result<Vec<Frame>, SourceClosureFailure>,
    pending: &mut Vec<Frame>,
    failures: &mut Vec<SourceClosureFailure>,
) -> Traversal {
    match outcome {
        Ok(next) => {
            pending.extend(next);
            Traversal::Continue
        }
        Err(failure) => collect(failure, failures),
    }
}

fn resolve<P: SourceSupply<RustFileInventory, RustSourceFault>>(
    store: &mut SourceStore,
    provider: &mut P,
    context: &ChildContext<'_>,
    walk: &mut Walk,
) -> Result<Vec<Frame>, SourceClosureFailure> {
    check_depth(store, context)?;
    match context.declaration.inline_scope {
        Some(scope) => inline_frames(store, context, (scope, walk)),
        None => external_frames(store, provider, context, walk),
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
            (scope, Arc::clone(&children), Arc::from(directory)),
            walk,
        )?);
    }
    Ok(frames)
}

fn inline_frame(
    context: &ChildContext<'_>,
    inline: (u32, Arc<[ModuleDeclaration]>, Arc<Path>),
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
        declared_directory: Arc::clone(&directory),
        directory,
        declarations: children,
        depth: context.depth,
        edition: context.frame.edition,
    })
}

fn external_frames<P: SourceSupply<RustFileInventory, RustSourceFault>>(
    store: &mut SourceStore,
    provider: &mut P,
    context: &ChildContext<'_>,
    walk: &mut Walk,
) -> Result<Vec<Frame>, SourceClosureFailure> {
    let site = module_site(context);
    let mut frames = Vec::new();
    for candidate in candidate_paths(store, context, &site)?.into_vec() {
        frames.extend(external_frame(
            store,
            provider,
            context,
            (&candidate, &site),
            walk,
        )?);
    }
    Ok(frames)
}

fn external_frame<P: SourceSupply<RustFileInventory, RustSourceFault>>(
    store: &mut SourceStore,
    provider: &mut P,
    context: &ChildContext<'_>,
    candidate: (&Path, &ClosureSite),
    walk: &mut Walk,
) -> Result<Option<Frame>, SourceClosureFailure> {
    let (candidate, site) = candidate;
    let canonical = store.canonical_inside(candidate, site)?;
    let path = store.intern(provider, &canonical, site, context.frame.edition)?;
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
        false => {
            let declared: Arc<Path> = Arc::from(file_directory(&canonical));
            Ok(Some(Frame {
                module,
                declarations: store.declarations((&*path, 0), site)?,
                source: path,
                directory: external_child_directory(&canonical, context, &declared),
                declared_directory: declared,
                depth: context.depth,
                edition: context.frame.edition,
            }))
        }
    }
}

fn module_site(context: &ChildContext<'_>) -> ClosureSite {
    ClosureSite::Module {
        file: Box::from(&*context.frame.source),
        module: Box::from(&*context.declaration.name),
    }
}
