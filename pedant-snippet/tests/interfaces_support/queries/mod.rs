//! The navigation questions one immutable index answers.
//!
//! Every module here reads the same mixed six-language repository the index
//! cases build, so all of them sit behind the shared complete-profile gate: an
//! outline claim about six languages cannot be made by a build that links four.

use crate::profile_gate::complete_profile_modules;

complete_profile_modules!(
    answer,
    binding,
    cursors,
    expectations,
    operation,
    outline,
    paging,
    projects,
    search,
    source,
    support,
);

#[cfg(feature = "test-support")]
complete_profile_modules!(reuse,);
