// Ungated test-only helper at top level.
pub fn build_for_tests() -> u32 {
    0
}

// Gated on the item itself.
#[cfg(feature = "test-support")]
pub fn make_fixture_for_tests() -> u32 {
    1
}

// Gated by the enclosing module.
#[cfg(feature = "test-support")]
pub mod test_helpers {
    pub fn seed_for_tests() {}
}

// Not gated: the module carries no feature gate.
pub mod util {
    pub fn cleanup_for_tests() {}
}

// Not a test-only API.
pub fn regular() {}

// Ungated test-only type.
pub struct scratch_for_tests;
