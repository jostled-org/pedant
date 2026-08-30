//! The one parse of the Go snapshot surface every ownership claim is answered
//! from.
//!
//! [`super::snapshot_ownership`] states what each owner must do and in what
//! order. This states how those owners are read: which files are parsed, how
//! often a parsed file reaches a route, and where in a named body that route
//! first appears. The two were one module until it passed the 500-line ceiling
//! the plan declares for a test module, and they answer different questions — a
//! reading is machinery, a claim is a sentence about the production tree.
//!
//! Twenty claims ask what an owner states. Reading per claim re-parsed the same
//! thirty-six files over and over, and — worse — let one claim range over a set
//! another never saw. So the surface is read once, here, and every claim is
//! handed that reading.

use crate::declaration_scan::{crate_path, parse_rust_file};
use crate::resolution::go::owners::{GO_MODULES, SNAPSHOT_MODULES};
use crate::resolution::go::scan::{
    SourceScan, impl_method, statement_naming, statement_naming_field,
};

/// The shared admission owners, relative to `src/resolution` rather than to the
/// Go tree.
///
/// Both are language-neutral, so no Go module may state what they state: the
/// single-site claims run the Go surface down to zero and the shared owner up to
/// one. The cache owns the order one physical source is read in; the store owns
/// the order one selected source is charged and retained in.
pub const CACHE: &str = "record_cache.rs";
pub const SNAPSHOT_STORE: &str = "snapshot_store.rs";
const NEUTRAL_OWNERS: &[&str] = &[CACHE, SNAPSHOT_STORE];

/// One statement of a production body, and how the scan names it.
///
/// A ceiling is a route a body takes; a retention is a method call on the field
/// holding the table, because `push` alone cannot tell one table from the queue
/// beside it.
#[derive(Clone, Copy)]
pub enum Named {
    /// A free or method call, named by the route it takes.
    Route(&'static str),
    /// A method call on a named field, named `field.method`.
    Growth(&'static str),
}

impl Named {
    /// The route this names, whichever form it takes.
    pub fn route(self) -> &'static str {
        match self {
            Self::Route(route) | Self::Growth(route) => route,
        }
    }

    /// How often one scanned owner states it.
    fn counted_in(self, scan: &SourceScan) -> usize {
        match self {
            Self::Route(route) => scan.reaches(route),
            Self::Growth(route) => scan.reaches_on_field(route),
        }
    }

    /// Where in one block it first appears.
    fn located_in(self, block: &syn::Block) -> Option<usize> {
        match self {
            Self::Route(route) => statement_naming(block, route),
            Self::Growth(route) => statement_naming_field(block, route),
        }
    }
}

/// One owner, parsed once, with the routes that parse showed it takes.
///
/// The tree is retained beside the counts because an ordering claim reads
/// statements out of a named method's block while a site claim counts the routes
/// the whole file takes. Dropping it meant re-parsing six files per claim.
struct GoOwner {
    file: syn::File,
    scan: SourceScan,
}

impl GoOwner {
    fn read(file: syn::File) -> Self {
        let scan = SourceScan::of_file(&file);
        Self { file, scan }
    }
}

/// The one reading every snapshot-ownership claim is answered from.
pub struct GoReading {
    /// Every Go module, in the order the model states it.
    modules: Box<[(&'static str, GoOwner)]>,
    /// The language-neutral admission owners, which are not Go modules and are
    /// scoped out of every site claim.
    neutral: Box<[(&'static str, GoOwner)]>,
}

impl GoReading {
    /// Read and parse the Go surface once, beside the shared owners.
    pub fn read() -> Self {
        // Both clauses are `all`, which holds over an emptied list. The scopes
        // below are what a site claim looks for an offender in, so an emptied
        // one reports no offender for any route and every scoped claim passes
        // on a surface nothing read. The widths are stated first for that
        // reason.
        assert!(
            !SNAPSHOT_MODULES.is_empty()
                && SNAPSHOT_MODULES.len() < GO_MODULES.len()
                && SNAPSHOT_MODULES
                    .iter()
                    .all(|module| GO_MODULES.contains(module)),
            "the snapshot stage is a proper subset of the Go surface, and a scoped claim reads \
             it from that one set"
        );
        assert!(
            !NEUTRAL_OWNERS.is_empty()
                && NEUTRAL_OWNERS
                    .iter()
                    .all(|owner| !GO_MODULES.contains(owner)),
            "a shared admission owner is language-neutral, and every site claim scopes it out"
        );
        Self {
            modules: GO_MODULES
                .iter()
                .map(|module| (*module, GoOwner::read(parsed("src/resolution/go", module))))
                .collect(),
            neutral: NEUTRAL_OWNERS
                .iter()
                .map(|owner| (*owner, GoOwner::read(parsed("src/resolution", owner))))
                .collect(),
        }
    }

    /// One inherent method of a retained owner, read from the one parse.
    ///
    /// A shared admission owner answers under its own module name, because the
    /// ordering claims read it beside the Go modules while every site claim
    /// scopes it out.
    pub fn method(&self, owner: &str, name: &str) -> &syn::ImplItemFn {
        let held = self.shared(owner).unwrap_or_else(|| self.owner(owner));
        impl_method(&held.file, name).unwrap_or_else(|| panic!("{owner} should declare `{name}`"))
    }

    /// The retained reading of one modelled Go module.
    fn owner(&self, module: &str) -> &GoOwner {
        self.modules
            .iter()
            .find(|(name, _)| *name == module)
            .map(|(_, held)| held)
            .unwrap_or_else(|| panic!("{module} is not a modelled Go module"))
    }

    /// The retained reading of one shared owner, or nothing when the name is a
    /// Go module's.
    fn shared(&self, owner: &str) -> Option<&GoOwner> {
        self.neutral
            .iter()
            .find(|(name, _)| *name == owner)
            .map(|(_, held)| held)
    }

    /// How often one shared owner states `named`.
    ///
    /// The name must be a shared admission owner's. A Go module answers through
    /// [`Self::stated_in`], which reports the scope it was found in.
    pub fn shared_count(&self, owner: &str, named: Named) -> usize {
        let held = self
            .shared(owner)
            .unwrap_or_else(|| panic!("{owner} is not a shared admission owner"));
        named.counted_in(&held.scan)
    }

    /// Which owners in `scope` state `named`, and how often.
    pub fn stated_in(&self, scope: &[&str], named: Named) -> Box<[(&'static str, usize)]> {
        self.modules
            .iter()
            .filter(|(module, _)| scope.contains(module))
            .map(|(module, held)| (*module, named.counted_in(&held.scan)))
            .filter(|(_, stated)| *stated > 0)
            .collect()
    }
}

/// The statement of `body` that first states `named`.
///
/// One lookup for every ordering claim, because fourteen spellings of one
/// absence message are fourteen chances to report the wrong body.
pub fn located(block: &syn::Block, body: &str, named: Named) -> usize {
    let route = named.route();
    named
        .located_in(block)
        .unwrap_or_else(|| panic!("`{body}` should state `{route}`"))
}

/// One owner, parsed from the tree that holds it.
fn parsed(tree: &str, module: &str) -> syn::File {
    parse_rust_file(&crate_path(tree).join(module))
}
