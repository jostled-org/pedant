//! The two pieces of mutable state a cache holds: the lock over one graph's
//! derived store, and the counters every classification is recorded against.
//!
//! Both must have exactly one owner. The lock owner must recover a poisoned
//! guard rather than abort and must clear the poison it recovered from, a
//! classification must be stated where the entry it describes was examined, and
//! a counter must never reach identity, record order, dense assembly, or a
//! derived algorithm, where it could make an answer depend on what a cache
//! happened to retain.
//!
//! Every scan here is two-directional. A model names who may hold a counter,
//! advance one, or read a statistic, and the whole production inventory is held
//! against that model, so a module that appeared and started counting fails
//! whether or not this file has heard of it.
//!
//! Every input is a compile-time source read through [`super::scan`].

use super::inventory::{PRODUCTION_SOURCES, SOURCES};
use super::scan::{
    code_only, compact, declaring_sources, method_body, method_body_of, naming, position_of,
    source, subject_methods,
};

/// The one module holding a cached graph's derived state behind a lock.
const DERIVED_OWNER: &str = "src/cache/analysis.rs";

/// The type that owns the lock over one graph's derived store.
const DERIVED_STATE: &str = "DerivedState";

/// The type that owns the two bounded stores behind that lock.
const DERIVED_STORE: &str = "Derived";

/// The one module that advances a cache counter.
const COUNTER_OWNER: &str = "src/cache/state.rs";

/// The one module that examines a retained source-unit projection.
const PROJECTION_OWNER: &str = "src/rust/reuse.rs";

/// The spellings a cache counter's storage is written with.
///
/// `Cell<u64>` and a bare `AtomicU64` are named because a second tally would be
/// declared with one of them; the two counter types are named because holding
/// either is what makes a module able to count at all.
const COUNTER_REPRESENTATIONS: &[&str] = &[
    "AtomicU64",
    "Cell<u64>",
    "CacheCounters",
    "CategoryCounters",
];

/// The only modules that may name a counter's storage.
///
/// One module declares the counters, the family root re-exports them, and four
/// holders carry the shared handle they record through. Nobody else may hold a
/// count at all.
const COUNTER_HOLDERS: &[&str] = &[
    "src/cache/analysis.rs",
    "src/cache/graph.rs",
    "src/cache/mod.rs",
    "src/cache/state.rs",
    "src/rust/cache.rs",
    "src/rust/reuse.rs",
];

/// The spellings a counter is advanced by.
const COUNTER_ADVANCES: &[&str] = &["fetch_add", "saturating_add", "wrapping_add"];

/// Every production source that advances a count, beside how many advances it
/// states.
///
/// Written down exactly rather than as a permitted set: a second module that
/// advanced a plain `u64` hit count would be a site this table does not hold,
/// and a module in the table that grew a second advance would state a count this
/// table does not match. Three of the four are arithmetic over stated totals —
/// the plan positions a Go build gives its modules, occurrence tallies, and the
/// one capacity owner's node and candidate totals — and none of them is a cache
/// statistic. The fourth is the cache's one saturating owner.
const COUNTER_ADVANCE_SITES: &[(&str, usize)] = &[
    ("src/cache/state.rs", 1),
    ("src/go/placement.rs", 1),
    ("src/projection/placement.rs", 1),
    ("src/projection/state.rs", 2),
];

/// The exact spellings a classification reaches a counter through.
///
/// The cached graph records through its own private helper; every other holder
/// records against the shared counters directly.
const UPDATE_CALLS: &[&str] = &["self.count(", ".record("];

/// The spellings a cache statistic is named by.
const STATISTIC_SPELLINGS: &[&str] = &["GraphCacheStats", "CacheCounters", "CacheEvent"];

/// The only modules that may name a cache statistic.
///
/// Every other production source is a counter-free owner: identity, record
/// order, dense assembly, and every derived algorithm answer from the facts they
/// were handed. A statistic that reached one of them could make an answer depend
/// on what a cache happened to retain.
const STATISTIC_READERS: &[&str] = &[
    "src/cache/analysis.rs",
    "src/cache/graph.rs",
    "src/cache/mod.rs",
    "src/cache/state.rs",
    "src/cache/stats.rs",
    "src/lib.rs",
    "src/rust/cache.rs",
    "src/rust/reuse.rs",
];

/// Every method `DerivedState` publishes to the crate, beside whether it reaches
/// the guarded store.
///
/// Compared as a whole list rather than searched: a fourth accessor that read
/// the store without the lock owner fails here, which an open-ended floor on the
/// number of acquisitions could never do.
const DERIVED_STATE_METHODS: &[(&str, bool)] = &[
    ("new", false),
    ("clear", true),
    ("indexed", true),
    ("product", true),
    ("counters", false),
];

/// The one owner of every derived-store lock recovers a poisoned guard, drops
/// what it retained, clears the poison, and cannot abort.
pub fn assert_poison_recovery_is_explicit_and_total() {
    let code = code_only(source(DERIVED_OWNER));
    assert_eq!(
        code.matches(".lock()").count(),
        1,
        "{DERIVED_OWNER} acquires the derived store in exactly one place"
    );
    assert_eq!(
        declaring_sources("Mutex"),
        vec![DERIVED_OWNER],
        "exactly one production source holds the derived state behind a lock"
    );

    let helper = method_body_of(DERIVED_OWNER, DERIVED_STATE, "locked");
    let recovered = position_of(&helper, "into_inner", "the lock owner");
    let dropped = position_of(&helper, "clear ()", "the lock owner");
    assert!(
        recovered < dropped,
        "the poisoned arm recovers the store and then clears it"
    );
    // Recovering ownership does not reset the flag, so an arm that stopped at
    // `into_inner` would take the poisoned branch for every later acquisition
    // and discard everything the graph retained from then on. The discard is
    // paid once, by the operation that observed the panic.
    let reset = position_of(&helper, "clear_poison ()", "the lock owner");
    assert!(
        recovered < reset,
        "the poisoned arm recovers the store before it clears the poison"
    );
    assert_eq!(
        code.matches("clear_poison").count(),
        1,
        "the flag is reset exactly where it is observed"
    );
    for forbidden in ["unwrap", "expect", "panic !", "unreachable !"] {
        assert!(
            !helper.contains(forbidden),
            "the lock owner must recover rather than abort: {forbidden}"
        );
    }

    assert_both_clears_drop_what_they_own();
    assert_the_store_is_reached_only_through_the_lock_owner();
    assert!(
        !code.contains("GraphAnalysisError::"),
        "{DERIVED_OWNER} must add no refusal to the analysis error vocabulary"
    );
}

/// Both methods spelled `clear` drop exactly what their own subject owns.
///
/// One file declares the name twice, on the store and on the state that guards
/// it. Naming the subject is what keeps the published one — the method
/// `CachedCodeGraph::clear_analysis_cache` reaches — from going unexamined
/// behind the private one.
fn assert_both_clears_drop_what_they_own() {
    let store = method_body_of(DERIVED_OWNER, DERIVED_STORE, "clear");
    for category in ["indexes . clear ()", "products . clear ()"] {
        assert!(
            store.contains(category),
            "recovery drops every retained category: {category}"
        );
    }
    let state = method_body_of(DERIVED_OWNER, DERIVED_STATE, "clear");
    assert!(
        state.contains("self . locked () . clear ()"),
        "the published clear reaches the lock owner and drops both stores through it"
    );
}

/// Every published method that reads the derived store reaches it through the
/// one lock owner, and nothing else names the mutex.
fn assert_the_store_is_reached_only_through_the_lock_owner() {
    let published: Vec<String> = subject_methods(DERIVED_OWNER, DERIVED_STATE)
        .into_iter()
        .filter(|method| method.visibility == "pub (crate)")
        .map(|method| method.name)
        .collect();
    assert_eq!(
        published,
        DERIVED_STATE_METHODS
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect::<Vec<String>>(),
        "{DERIVED_STATE} publishes exactly the methods this case reads"
    );
    for (name, reaches) in DERIVED_STATE_METHODS {
        let body = method_body_of(DERIVED_OWNER, DERIVED_STATE, name);
        assert_eq!(
            body.contains("self . locked ()"),
            *reaches,
            "{DERIVED_STATE}::{name} reaches the lock owner exactly when it reads the store"
        );
    }
    let reaching = DERIVED_STATE_METHODS
        .iter()
        .filter(|(_, reaches)| *reaches)
        .count();
    let compacted = compact(source(DERIVED_OWNER));
    assert_eq!(
        compacted.matches("self.locked()").count(),
        reaching,
        "every derived read and write reaches the one lock owner, and nothing else does"
    );
    assert_eq!(
        compacted.matches("self.retained").count(),
        2,
        "the guarded store is named by the lock owner alone, to acquire it and to \
         clear its poison"
    );
}

/// Every examined source is classified where it was examined.
///
/// A hit and a miss describe one decision, so both belong to the lookup that
/// took it. Recording the miss in the retention that may follow instead leaves
/// a source whose derivation refused examined and classified as neither, which
/// is the one reading a caller cannot reconstruct from the counters afterwards.
fn assert_classification_belongs_to_the_examination() {
    let examined = method_body(PROJECTION_OWNER, "reused");
    for classification in ["CacheEvent :: Hit", "CacheEvent :: Miss"] {
        assert!(
            examined.contains(classification),
            "the lookup that examines a source states {classification}"
        );
    }
    let retention = method_body(PROJECTION_OWNER, "retain");
    for forbidden in ["CacheEvent :: Hit", "CacheEvent :: Miss"] {
        assert!(
            !retention.contains(forbidden),
            "retention counts pressure, never an examination: {forbidden}"
        );
    }
    assert!(
        retention.contains("CacheEvent :: Eviction"),
        "retention still counts the entries its ceiling dropped"
    );
}

/// Every counter mutation reaches one saturating owner, and no statistic
/// reaches identity, order, assembly, or an algorithm.
pub fn assert_counter_updates_are_saturating_and_single_owned() {
    assert_classification_belongs_to_the_examination();
    let owner = code_only(source(COUNTER_OWNER));
    for declaration in ["fn saturate(", "pub(crate) fn record("] {
        assert_eq!(
            owner.matches(declaration).count(),
            1,
            "{COUNTER_OWNER} declares {declaration} exactly once"
        );
    }
    assert!(
        method_body(COUNTER_OWNER, "record").contains("saturate ("),
        "the one mutation path reaches the saturating owner"
    );

    assert_counter_storage_is_held_by_its_owners();
    assert_every_advance_is_a_modelled_site();
    assert_classifications_are_stated_inside_an_update();
    assert_statistics_reach_only_their_readers();
}

/// Nobody outside the modelled holders names a counter's storage.
fn assert_counter_storage_is_held_by_its_owners() {
    assert_is_modelled(COUNTER_HOLDERS, "counter holder");
    let offenders = sources_naming(
        COUNTER_REPRESENTATIONS,
        COUNTER_HOLDERS,
        "the counter storage",
    );
    assert!(
        offenders.is_empty(),
        "a counter is held by exactly the modelled owners: {offenders:?}"
    );
}

/// Every advance the crate states is one the model already named, and nobody
/// states one the model does not count.
///
/// The one saturating cache owner is proved by the site table, not by exempting
/// a spelling: a second module advancing its own hit count with the same
/// arithmetic is a site with no entry, and fails.
fn assert_every_advance_is_a_modelled_site() {
    let modelled: Vec<&str> = COUNTER_ADVANCE_SITES
        .iter()
        .map(|(path, _)| *path)
        .collect();
    assert_is_modelled(&modelled, "counter advance site");
    let offenders: Vec<String> = PRODUCTION_SOURCES
        .iter()
        .filter_map(|path| {
            let code = compact(source(path));
            let stated: usize = COUNTER_ADVANCES
                .iter()
                .map(|spelling| code.matches(spelling).count())
                .sum();
            let expected = COUNTER_ADVANCE_SITES
                .iter()
                .find(|(site, _)| site == path)
                .map_or(0, |(_, count)| *count);
            match stated == expected {
                true => None,
                false => Some(format!("{path} advances {stated} rather than {expected}")),
            }
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "every counter advance is a modelled site: {offenders:?}"
    );
}

/// Every classification a module states sits inside a call to the one update
/// helper it records through.
///
/// Counted per site rather than per file. A file exempted because it happens to
/// call an update somewhere else could state a classification in an ad-hoc
/// branch that reaches no counter at all, which is a decision the counters would
/// then never show.
fn assert_classifications_are_stated_inside_an_update() {
    let offenders: Vec<String> = SOURCES
        .iter()
        .filter(|entry| entry.path != COUNTER_OWNER)
        .filter_map(|entry| {
            let code = compact(entry.text);
            let stated = code.matches("CacheEvent::").count();
            let recorded = classifications_inside_updates(&code);
            match stated == recorded {
                true => None,
                false => Some(format!(
                    "{} states {stated} and records {recorded}",
                    entry.path
                )),
            }
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "a classification is only ever stated inside the one update call: {offenders:?}"
    );
}

/// How many classifications one compacted source states inside an update call.
fn classifications_inside_updates(code: &str) -> usize {
    UPDATE_CALLS
        .iter()
        .flat_map(|call| {
            code.match_indices(call)
                .map(|(at, spelling)| at + spelling.len())
        })
        .filter_map(|from| code[from..].split(')').next())
        .map(|arguments| arguments.matches("CacheEvent::").count())
        .sum()
}

/// No statistic reaches identity, record order, dense assembly, or a derived
/// algorithm.
fn assert_statistics_reach_only_their_readers() {
    assert_is_modelled(STATISTIC_READERS, "statistic reader");
    let offenders = sources_naming(STATISTIC_SPELLINGS, STATISTIC_READERS, "the statistic");
    assert!(
        offenders.is_empty(),
        "a statistic cannot reach identity, order, assembly, or an algorithm: {offenders:?}"
    );
}

/// Every production source outside `permitted` that names one of `spellings`.
fn sources_naming(spellings: &[&str], permitted: &[&str], vocabulary: &str) -> Vec<String> {
    let scanned: Vec<&str> = PRODUCTION_SOURCES
        .iter()
        .copied()
        .filter(|path| !permitted.contains(path))
        .collect();
    naming(&scanned, spellings, vocabulary)
}

/// Every path an allow-list names is a production source this crate scans.
///
/// Without this the lists above would narrow silently: a renamed module would
/// leave behind an entry that exempts nothing and a file that nothing exempts.
fn assert_is_modelled(paths: &[&str], subject: &str) {
    let unknown: Vec<&&str> = paths
        .iter()
        .filter(|path| !PRODUCTION_SOURCES.contains(path))
        .collect();
    assert!(
        unknown.is_empty(),
        "every modelled {subject} is a scanned production source: {unknown:?}"
    );
}
