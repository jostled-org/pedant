//! The physical declaration sites one Rust extraction retains.
//!
//! The table below is this recognizer's own statement of the Rust row of the
//! structure contract. `pedant-syntax` states the same row for its loose `syn`
//! route, and neither crate links the other's recognizer: this one takes
//! `pedant-syntax` with the Go grammar alone. The comparison that binds the two
//! is owned by `six_language_outline_is_complete_nested_and_source_exact` at the
//! `pedant-snippet` root, which is the first root that links both.

use pedant_core::ir::{FileIr, IrRange, StructureSite, extract};
use pedant_types::StructureKind;
use syn::spanned::Spanned;
use syn::visit::Visit;

/// The production declaration-extent owner.
const EXTENT_IMPLEMENTATION: &str = include_str!("../../../../src/ir/extract/extent.rs");

/// The two production dispatch routes that formerly spanned whole items.
const IMPL_DISPATCH: &str = include_str!("../../../../src/ir/extract/impls.rs");
const ITEM_DISPATCH: &str = include_str!("../../../../src/ir/extract/visitor/implementation.rs");

/// One Rust source stating every structure the Rust row of the contract names.
///
/// It declares `Output` and `run` twice — once in a trait, once in the impl
/// that satisfies it — because equal names at different sites are exactly what
/// a join on names would merge.
///
/// The `shapes` module states one declaration per boundary token the extent
/// owner reads: tuple and unit structs, an external `mod`, a defaulted trait
/// method, each of the four signature qualifiers, `default` associated items,
/// `unsafe` and `auto` traits, `unsafe` and `default` impls, a restricted
/// visibility, and an item whose only attribute is an inner one. A wrong head
/// or tail arm shifts every declaration of its class, and the parity oracle
/// below reaches an arm only where the source writes the form that selects it.
const SOURCE: &str = "\
#[allow(dead_code)]
pub mod inner {
    pub struct Job {
        id: u32,
    }

    pub enum Mode {
        Fast,
    }

    pub union Bits {
        raw: u32,
    }

    pub trait Run {
        type Output;
        fn run(&self) -> Self::Output;
    }

    pub type Alias = u32;

    pub const LIMIT: u32 = 3;

    pub static NAME: &str = \"job\";

    impl Job {
        pub const ZERO: u32 = 0;

        pub fn new() -> Self {
            Job { id: 0 }
        }

        pub fn id(&self) -> u32 {
            self.id
        }
    }

    impl Run for Job {
        type Output = u32;

        fn run(&self) -> u32 {
            self.id
        }
    }
}

pub fn entry() {}

pub mod shapes {
    #![allow(unused)]

    pub struct Pair(u32, u32);

    pub struct Unit;

    pub(crate) const SCALE: u32 = 2;

    mod external;

    unsafe trait Danger {
        fn peek(&self) -> u32 {
            1
        }
    }

    auto trait Marker {}

    pub struct Holder;

    unsafe impl Danger for Holder {
        fn peek(&self) -> u32 {
            2
        }
    }

    impl Holder {
        const fn size() -> u32 {
            1
        }

        async fn load(&self) {}

        unsafe fn raw(&self) {}

        extern \"C\" fn abi() {}
    }

    pub trait Fill {
        type Slot;

        fn fill(&self);
    }

    default impl<T> Fill for T {
        default type Slot = u32;

        default fn fill(&self) {}
    }
}
";

/// The path every extraction here is taken under.
const PATH: &str = "code_intelligence_sites.rs";

/// One structure's kind, declared name, and owner position.
type StructureRow<'source> = (StructureKind, Option<&'source str>, Option<usize>);

/// Every structure this source states: its kind, its name, and the position of
/// the declaration that owns it.
const EXPECTED: &[StructureRow<'static>] = &[
    (StructureKind::Module, Some("inner"), None),
    (StructureKind::Struct, Some("Job"), Some(0)),
    (StructureKind::Enum, Some("Mode"), Some(0)),
    (StructureKind::Union, Some("Bits"), Some(0)),
    (StructureKind::Trait, Some("Run"), Some(0)),
    (StructureKind::TypeAlias, Some("Output"), Some(4)),
    (StructureKind::Method, Some("run"), Some(4)),
    (StructureKind::TypeAlias, Some("Alias"), Some(0)),
    (StructureKind::Constant, Some("LIMIT"), Some(0)),
    (StructureKind::Static, Some("NAME"), Some(0)),
    (StructureKind::Impl, None, Some(0)),
    (StructureKind::Constant, Some("ZERO"), Some(10)),
    (StructureKind::Function, Some("new"), Some(10)),
    (StructureKind::Method, Some("id"), Some(10)),
    (StructureKind::Impl, None, Some(0)),
    (StructureKind::TypeAlias, Some("Output"), Some(14)),
    (StructureKind::Method, Some("run"), Some(14)),
    (StructureKind::Function, Some("entry"), None),
    (StructureKind::Module, Some("shapes"), None),
    (StructureKind::Struct, Some("Pair"), Some(18)),
    (StructureKind::Struct, Some("Unit"), Some(18)),
    (StructureKind::Constant, Some("SCALE"), Some(18)),
    (StructureKind::Module, Some("external"), Some(18)),
    (StructureKind::Trait, Some("Danger"), Some(18)),
    (StructureKind::Method, Some("peek"), Some(23)),
    (StructureKind::Trait, Some("Marker"), Some(18)),
    (StructureKind::Struct, Some("Holder"), Some(18)),
    (StructureKind::Impl, None, Some(18)),
    (StructureKind::Method, Some("peek"), Some(27)),
    (StructureKind::Impl, None, Some(18)),
    (StructureKind::Function, Some("size"), Some(29)),
    (StructureKind::Method, Some("load"), Some(29)),
    (StructureKind::Method, Some("raw"), Some(29)),
    (StructureKind::Function, Some("abi"), Some(29)),
    (StructureKind::Trait, Some("Fill"), Some(18)),
    (StructureKind::TypeAlias, Some("Slot"), Some(34)),
    (StructureKind::Method, Some("fill"), Some(34)),
    (StructureKind::Impl, None, Some(18)),
    (StructureKind::TypeAlias, Some("Slot"), Some(37)),
    (StructureKind::Method, Some("fill"), Some(37)),
];

/// One extraction retains every full declaration site, its owner ordinal, and
/// the exact definition ordinal it states.
#[test]
fn rust_file_inventory_retains_full_structure_sites_and_definition_ordinals() {
    let ir = extracted();
    complete_sites_are_retained_in_source_order(&ir);
    every_named_site_names_its_own_definition(&ir);
    an_impl_block_states_a_site_and_no_definition(&ir);
    equal_names_at_two_sites_name_two_definitions(&ir);
    #[cfg(feature = "resolution-test-support")]
    one_visit_fills_both_tables();
}

/// Boundary-token extents retain the ranges the former whole-item span route
/// reported, while production never asks `Spanned` to tokenize an item.
#[test]
fn rust_declaration_extents_keep_spanned_parity_without_spanning_items() {
    let syntax = syn::parse_file(SOURCE).expect("the fixture parses");
    let mut spanned = SpannedDeclarations::default();
    spanned.visit_file(&syntax);
    let tracked = spanned.rows();
    let retained: Box<[IrRange]> = extract(PATH, &syntax, None)
        .structure_sites
        .iter()
        .map(|site| site.range)
        .collect();
    assert_eq!(
        retained.len(),
        tracked.len(),
        "boundary tokens retain one extent per structure the source states"
    );
    for (position, (row, oracle)) in tracked.iter().enumerate() {
        assert_eq!(
            retained.get(position),
            Some(oracle),
            "{row:?} keeps the tracked whole-item span answer"
        );
    }

    assert!(
        !EXTENT_IMPLEMENTATION.contains("spanned::Spanned"),
        "the extent owner must not import the whole-item spanning route"
    );
    for (path, source) in [
        ("extent.rs", EXTENT_IMPLEMENTATION),
        ("impls.rs", IMPL_DISPATCH),
        ("visitor/implementation.rs", ITEM_DISPATCH),
    ] {
        assert!(
            !source.contains("node.span()") && !source.contains("item.span()"),
            "{path} must read declaration boundary tokens rather than span a whole item"
        );
    }
}

/// The prior declaration-range route, retained only as the parity oracle.
#[derive(Default)]
struct SpannedDeclarations {
    ranges: Vec<IrRange>,
}

impl SpannedDeclarations {
    /// Every retained range, paired with the row of [`EXPECTED`] it answers for.
    ///
    /// The oracle walks the declarations that table writes down, so the pairing
    /// is total and the lengths are the same claim. Pairing them here rather
    /// than comparing two bare range slices gives a mismatch the declaration it
    /// belongs to: a bare slice comparison names an index, and an index into a
    /// forest of eighteen sites is not a declaration a reader can find.
    fn rows(&self) -> Box<[(StructureRow<'static>, IrRange)]> {
        assert_eq!(
            self.ranges.len(),
            EXPECTED.len(),
            "the parity oracle reaches every structure the source states"
        );
        EXPECTED
            .iter()
            .copied()
            .zip(self.ranges.iter().copied())
            .collect()
    }

    fn retain(&mut self, node: &impl Spanned) {
        let span = node.span();
        let range = IrRange {
            start: pedant_core::ir::IrSpan {
                line: span.start().line,
                column: span.start().column,
            },
            end: pedant_core::ir::IrSpan {
                line: span.end().line,
                column: span.end().column,
            },
        };
        self.ranges.push(range);
    }
}

impl<'ast> Visit<'ast> for SpannedDeclarations {
    fn visit_item(&mut self, node: &'ast syn::Item) {
        self.retain(node);
        syn::visit::visit_item(self, node);
    }

    fn visit_impl_item(&mut self, node: &'ast syn::ImplItem) {
        self.retain(node);
        syn::visit::visit_impl_item(self, node);
    }

    fn visit_trait_item(&mut self, node: &'ast syn::TraitItem) {
        self.retain(node);
        syn::visit::visit_trait_item(self, node);
    }
}

/// The IR of [`SOURCE`].
fn extracted() -> FileIr {
    let syntax = syn::parse_file(SOURCE).expect("the fixture parses");
    extract(PATH, &syntax, None)
}

/// Every declaration is retained once, in source order, owned by the nearest
/// declaration that contains it.
fn complete_sites_are_retained_in_source_order(ir: &FileIr) {
    let stated: Box<[StructureRow<'_>]> = ir
        .structure_sites
        .iter()
        .map(|site| (site.kind, declared_name(ir, site), owner_position(site)))
        .collect();
    assert_eq!(
        &*stated, EXPECTED,
        "the extraction retains every declaration the source writes, in order"
    );

    for (position, site) in ir.structure_sites.iter().enumerate() {
        assert!(
            owner_position(site).is_none_or(|parent| parent < position),
            "site {position} is owned by an earlier position, so the forest is acyclic"
        );
        assert_eq!(
            owner_position(site),
            nearest_owner(&ir.structure_sites, position),
            "site {position} names the nearest declaration containing it"
        );
    }
}

/// The table position one site names as its owner.
///
/// The site holds an identity rather than a number, so a comparison against a
/// position asks for the position that identity names.
fn owner_position(site: &StructureSite) -> Option<usize> {
    site.parent.map(|owner| owner.index())
}

/// The name one site declares, which it states through its definition ordinal
/// rather than through a second copy of the string.
fn declared_name<'ir>(ir: &'ir FileIr, site: &StructureSite) -> Option<&'ir str> {
    let ordinal = site.definition?;
    ir.definition_sites
        .get(ordinal.index())
        .map(|definition| &*definition.name)
}

/// The position of the smallest other site whose range strictly contains this
/// one's.
fn nearest_owner(sites: &[StructureSite], position: usize) -> Option<usize> {
    let range = sites[position].range;
    sites
        .iter()
        .enumerate()
        .filter(|(candidate, site)| *candidate != position && strictly_contains(site.range, range))
        .min_by_key(|(_, site)| extent(site.range))
        .map(|(candidate, _)| candidate)
}

/// Whether `outer` covers `inner` and is not the same extent.
fn strictly_contains(outer: IrRange, inner: IrRange) -> bool {
    point(outer.start) <= point(inner.start)
        && point(inner.end) <= point(outer.end)
        && (point(outer.start), point(outer.end)) != (point(inner.start), point(inner.end))
}

/// One range's endpoints, as a comparable pair.
fn point(at: pedant_core::ir::IrSpan) -> (usize, usize) {
    (at.line, at.column)
}

/// A range's size, in lines and then columns, for choosing the nearest owner.
fn extent(range: IrRange) -> (usize, usize) {
    (
        range.end.line.saturating_sub(range.start.line),
        range.end.column,
    )
}

/// Every named site names a definition this file holds, and that definition's
/// name range sits inside the declaration the site covers.
///
/// The site covers the whole declaration and the definition covers the name
/// alone, so a site whose ordinal pointed at another declaration's definition
/// would fail the containment rather than merely disagree about a string. The
/// ordinal is also the only place the name lives, so a site cannot be named and
/// definitionless the way two separate fields could be.
fn every_named_site_names_its_own_definition(ir: &FileIr) {
    for (position, site) in ir.structure_sites.iter().enumerate() {
        let Some(ordinal) = site.definition else {
            continue;
        };
        let definition = ir
            .definition_sites
            .get(ordinal.index())
            .unwrap_or_else(|| panic!("site {position} names a definition this file holds"));
        assert_eq!(
            StructureKind::from(definition.kind),
            site.kind,
            "site {position} agrees with its definition about what it declares"
        );
        assert!(
            strictly_contains(site.range, definition.range),
            "site {position} covers the whole declaration its definition names"
        );
    }
}

/// An `impl` block states a physical site, owns the items inside it, and
/// invents no definition.
fn an_impl_block_states_a_site_and_no_definition(ir: &FileIr) {
    let blocks: Box<[(usize, &StructureSite)]> = ir
        .structure_sites
        .iter()
        .enumerate()
        .filter(|(_, site)| site.kind == StructureKind::Impl)
        .collect();
    assert_eq!(blocks.len(), 5, "the fixture states five impl blocks");
    for (position, block) in blocks {
        assert_eq!(
            block.definition, None,
            "an impl block declares no name, so it invents no definition ordinal"
        );
        assert!(
            ir.structure_sites
                .iter()
                .any(|site| owner_position(site) == Some(position)),
            "impl block {position} owns the items its body states"
        );
    }
    assert!(
        ir.definition_sites
            .iter()
            .all(|definition| !definition.name.is_empty()),
        "no definition was minted for an unnamed declaration"
    );
}

/// Two declarations sharing a name name two definitions.
fn equal_names_at_two_sites_name_two_definitions(ir: &FileIr) {
    for name in ["Output", "run"] {
        let ordinals: Box<[usize]> = ir
            .structure_sites
            .iter()
            .filter(|site| declared_name(ir, site) == Some(name))
            .filter_map(|site| site.definition)
            .map(|ordinal| ordinal.index())
            .collect();
        assert_eq!(ordinals.len(), 2, "{name} is declared at two sites");
        assert_ne!(
            ordinals[0], ordinals[1],
            "{name}'s two sites name their own definitions rather than one shared ordinal"
        );
    }
}

/// One visit fills the definition table and the structure table together.
///
/// A second walk could produce the same tables and still be a second walk, so
/// the claim is read from the production visitor's own observation rather than
/// from its output.
#[cfg(feature = "resolution-test-support")]
fn one_visit_fills_both_tables() {
    let probe = pedant_core::resolution::ResolutionProbe::install();
    let ir = extracted();
    assert_eq!(
        &*probe.site_visits(),
        [Box::<str>::from(PATH)],
        "one extraction walks the source once"
    );
    assert!(
        !ir.structure_sites.is_empty() && !ir.definition_sites.is_empty(),
        "that one walk filled both tables"
    );
}
