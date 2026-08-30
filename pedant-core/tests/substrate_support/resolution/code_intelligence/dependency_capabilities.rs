//! What the admitted code-intelligence closure is allowed to do.
//!
//! The closure is a watcher, an ignore walker, a digest, and four first-party
//! substrates. Together they may read source bytes, observe a directory, hash
//! what they read, parse it, resolve it, and project it into a graph. They may
//! not write, spawn, or open a socket.
//!
//! A forbid over a capability profile is an `all` over what is normally an
//! empty finding set, so a detector that had stopped reporting would satisfy it
//! by reporting nothing. The tracked profile answers that with a sentinel
//! mirror; this root answers it with the production detector itself, run over
//! two sentinels whose expected answers differ.
//!
//! Both sentinels are handed to the detector as the text they already are. The
//! detector takes a name and a parsed file and never opens a path, so writing
//! them to a temporary directory and reading them back proved nothing about the
//! detector and put an `fs::write` inside the case whose whole subject is a
//! product that must not write.

use std::collections::BTreeSet;

use pedant_core::capabilities::detect_capabilities;
use pedant_core::ir::extract;
use pedant_types::Capability;

use crate::resolution::authority_scan::read_text;
use crate::resolution::code_intelligence::dependency_attestation::assert_every_admitted_dependency_carries_an_audit;
use crate::resolution::code_intelligence::dependency_model::{
    ADMITTED_DEPENDENCIES, CAPABILITY_CHECK, CAPABILITY_PROFILE_OWNERS, CLOSURE_CHECK,
    CONFIGURATION_CHECK, FORBIDDEN_CAPABILITIES, READ_ONLY_CAPABILITIES, SYNTAX_CAPABILITY_CHECK,
};
use crate::resolution::tracked_script::assert_checks_are_executable_linted_and_in_ci;

/// A source that reads, walks, and hashes, and does nothing else.
const READ_ONLY_SENTINEL: &str = "\
use sha2::Digest;

pub fn read(path: &str) -> std::io::Result<String> {
    std::fs::read_to_string(path)
}

pub fn walk(root: &str) -> std::io::Result<std::fs::ReadDir> {
    std::fs::read_dir(root)
}

pub fn digest(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}
";

/// A source that writes, spawns, and connects.
const FORBIDDEN_SENTINEL: &str = "\
pub fn store(path: &str) -> std::io::Result<()> {
    std::fs::write(path, \"sentinel\")
}

pub fn spawn() -> std::io::Result<std::process::Child> {
    std::process::Command::new(\"ls\").spawn()
}

pub fn connect() -> std::io::Result<std::net::TcpStream> {
    std::net::TcpStream::connect(\"sentinel.invalid:80\")
}
";

/// 4.T3 (Invariant 16): the admitted dependency closure states read-only
/// capabilities, a committed pedant audit says so of each third-party crate, the
/// tracked profile that holds the first-party tree to the same terms is
/// registered and exact, and the detector behind that profile still reports a
/// write, a spawn, and a socket.
#[test]
fn code_intelligence_dependency_capabilities_are_read_only() {
    assert_every_admitted_dependency_states_a_read_only_capability();
    assert_every_admitted_dependency_carries_an_audit();
    assert_the_tracked_owners_are_registered_and_exact();
    assert_the_detector_separates_the_two_sentinels();
}

/// Every admitted crate states a capability inside the read-only set, and the
/// set the whole closure states is disjoint from the forbidden one.
fn assert_every_admitted_dependency_states_a_read_only_capability() {
    assert!(
        !ADMITTED_DEPENDENCIES.is_empty(),
        "a capability claim over no admitted dependency constrains nothing"
    );
    let stated = admitted_capabilities();
    let admitted: BTreeSet<Capability> = READ_ONLY_CAPABILITIES.iter().copied().collect();
    let outside: Box<[Capability]> = stated.difference(&admitted).copied().collect();
    assert!(
        outside.is_empty(),
        "the admitted closure states capabilities outside the read-only set: {outside:?}"
    );
    let forbidden: Box<[Capability]> = FORBIDDEN_CAPABILITIES
        .iter()
        .copied()
        .filter(|capability| stated.contains(capability))
        .collect();
    assert!(
        forbidden.is_empty(),
        "the admitted closure states a write, spawn, or network capability: {forbidden:?}"
    );
}

/// The capabilities the whole admitted closure states, as a set.
fn admitted_capabilities() -> BTreeSet<Capability> {
    ADMITTED_DEPENDENCIES
        .iter()
        .map(|admitted| admitted.capability.stated_capability())
        .collect()
}

/// The four durable checks are executable, linted, and run by CI. Every owner
/// ruling on the product tree states its range and non-vacuity predicate.
fn assert_the_tracked_owners_are_registered_and_exact() {
    assert_checks_are_executable_linted_and_in_ci(&[
        CLOSURE_CHECK,
        CAPABILITY_CHECK,
        CONFIGURATION_CHECK,
        SYNTAX_CAPABILITY_CHECK,
    ]);

    // Both first-party profile owners are read: one admits the product's exact
    // read/digest/exit-status/elapsed-time set, and one requires the syntax
    // substrate to remain empty. The floor is the one `ADMITTED_DEPENDENCIES`
    // carries above: an emptied table skips the loop, and the helper-name
    // assertions inside it then hold over nothing.
    assert!(
        !CAPABILITY_PROFILE_OWNERS.is_empty(),
        "a non-vacuity claim over no profile owner constrains nothing"
    );
    for (check, trees, predicate) in CAPABILITY_PROFILE_OWNERS {
        assert_profile_owner_is_non_vacuous(check, trees, predicate);
    }
}

/// One tracked owner ranges over the trees it rules on and reaches its profile
/// through the sentinel-backed helpers, so its forbid is not vacuous.
///
/// The caller names the profile predicate that belongs to this owner. The
/// product uses the read/digest/exit-status/elapsed-time predicate; the syntax
/// substrate uses the empty-profile predicate. Both use the same detector-live
/// proof before evaluating their distinct contracts.
///
/// The two helper names are the whole non-vacuity claim, so every reader that
/// makes it makes it here. A second copy is a second list of helpers, and the
/// copy that fell behind would report a rewritten script as still exact.
pub(crate) fn assert_profile_owner_is_non_vacuous(check: &str, trees: &[&str], predicate: &str) {
    assert!(
        !trees.is_empty(),
        "{check} is modelled as ruling on the product and names no tree, so the range check \
         reads nothing"
    );
    let text = read_text(check);
    for tree in trees {
        assert!(text.contains(tree), "{check} must range over {tree}");
    }
    for helper in ["assert_capability_detectors_live", predicate] {
        assert!(
            text.contains(helper),
            "{check} must reach the profile through {helper}, so its forbid is not vacuous"
        );
    }
}

/// The production detector reports exactly the admitted capabilities for a
/// read-only sentinel and every forbidden one for a sentinel that writes,
/// spawns, and connects.
///
/// Both halves are needed. Without the first, a detector that reported every
/// capability for every input would pass the second; without the second, a
/// detector that reported nothing would pass the first.
fn assert_the_detector_separates_the_two_sentinels() {
    assert_eq!(
        detected_capabilities("read_only.rs", READ_ONLY_SENTINEL),
        admitted_capabilities(),
        "the read-only sentinel must state exactly the capabilities the admitted closure states"
    );

    let reported = detected_capabilities("forbidden.rs", FORBIDDEN_SENTINEL);
    let missed: Box<[Capability]> = FORBIDDEN_CAPABILITIES
        .iter()
        .copied()
        .filter(|capability| !reported.contains(capability))
        .collect();
    assert!(
        missed.is_empty(),
        "the detector no longer reports {missed:?}, so every read-only claim over it is vacuous"
    );
}

/// Every capability the production detector reports for one sentinel.
///
/// The name is the one the detector labels its findings with, and it is all the
/// detector ever wanted: nothing here resolves a path.
fn detected_capabilities(name: &str, source: &str) -> BTreeSet<Capability> {
    let syntax =
        syn::parse_file(source).unwrap_or_else(|error| panic!("{name} should parse: {error}"));
    let ir = extract(name, &syntax, None);
    detect_capabilities(&ir, None)
        .profile
        .findings
        .iter()
        .map(|finding| finding.capability)
        .collect()
}
