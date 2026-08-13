//! The indexed proof that the committed tree keeps one owner per resolution
//! decision and does not restore removed authorities.

use crate::resolution::authority_scan::{
    assert_authorities, assert_migrated_predicates, assert_removed_authorities_are_absent,
    first_party_sources,
};

#[test]
fn first_party_authorities_removed_names_and_migrated_cases_are_exact() {
    let sources = first_party_sources();

    assert_authorities(sources);
    assert_removed_authorities_are_absent(sources);
    assert_migrated_predicates();
}
