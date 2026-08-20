//! The host-independence claim, read from the production source.
//!
//! A snapshot that consulted the running machine would still pass every
//! behavioral row on the machine that wrote it: the predicates would simply be
//! resolved the same way twice. So the complete Go project, snapshot, and
//! resolution closure is read instead, and every way this process could learn
//! which build it is part of is named and refused.

use crate::resolution::go::owners::{GO_MODULES, SNAPSHOT_MODULES, source_closure, text_offenders};

/// Every route to host selection state, with the complete set of owners
/// allowed to name it.
///
/// Each entry is the text that would prove the read. The operating-system and
/// architecture terms a file name may end with are a written-down table in the
/// condition owner, so a term appearing there is data rather than a lookup —
/// but the environment names that would select between them appear nowhere.
const HOST_STATE: &[(&str, &[&str])] = &[
    ("std::env", &[]),
    ("env::var", &[]),
    ("var_os", &[]),
    ("env!", &[]),
    ("option_env!", &[]),
    ("consts::OS", &[]),
    ("consts::ARCH", &[]),
    ("consts::FAMILY", &[]),
    ("target_os", &[]),
    ("target_arch", &[]),
    ("target_env", &[]),
    ("cfg!", &[]),
    ("CGO_ENABLED", &[]),
    ("GOOS", &[]),
    ("GOARCH", &[]),
    ("GOFLAGS", &[]),
    ("GOPATH", &[]),
    ("GOROOT", &[]),
    ("GOMODCACHE", &[]),
    ("go.work", &[]),
    ("std::process", &[]),
    ("Command", &[]),
    ("std::net", &[]),
    ("SystemTime", &[]),
    ("Instant", &[]),
];

/// 4.T5 (Invariants 4, 19): the complete Go project, snapshot, and resolution
/// closure reads no environment, platform, clock, process, or network state, so
/// one repository state states one snapshot on every host.
#[test]
fn go_snapshot_and_resolver_read_no_host_selection_state() {
    let closure = source_closure();
    assert!(
        closure.len() > SNAPSHOT_MODULES.len(),
        "the closure must reach the shared resolution owners too"
    );
    for owner in SNAPSHOT_MODULES {
        assert!(
            GO_MODULES.contains(owner),
            "{owner} is a snapshot owner and must be inside the scanned closure"
        );
    }

    let offenders = text_offenders(HOST_STATE);
    assert!(
        offenders.is_empty(),
        "the Go snapshot closure reads host selection state: {offenders:?}"
    );
}
