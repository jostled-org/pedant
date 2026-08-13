//! Inline-module path overrides declared from external source files.

use crate::resolution::closure_asserts;

#[test]
fn external_source_inline_paths_resolve_from_the_declaring_directory() {
    closure_asserts::assert_external_source_inline_paths_use_declaring_directory();
}
