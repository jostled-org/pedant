//! The repository index cases.
//!
//! Every module but [`profiles`] states a claim about a mixed six-language
//! repository, so all of them need the whole closed language and graph
//! selection that [`profile_gate`](crate::profile_gate) states. `profiles` is
//! the one that has to run in every profile, so it sits outside that gate.
//!
//! [`fixture`], [`sources`], and [`harness`] are reachable from the whole test
//! crate: the navigation cases index the same mixed repository, and a second
//! copy of it would be a second repository two claims could quietly disagree
//! about. All three are gated too, because all three exist only to state that
//! repository, and [`root`] is the one piece of them a reduced profile still
//! needs.

use crate::profile_gate::complete_profile_modules;

mod profiles;
pub(crate) mod root;

complete_profile_modules!(
    fixture,
    harness,
    accounting,
    confinement,
    corpus,
    failures,
    graphs,
    identity,
    keys,
    owners,
    sources,
    state_identity,
);

#[cfg(feature = "test-support")]
complete_profile_modules!(claims, framing, payloads, read_probe, reuse,);
