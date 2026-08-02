//! Bash backend: function definitions with and without the `function`
//! keyword.

use pedant_syntax::{LineSpan, SourceUnitKind};

use crate::fixtures::{BASH, Row};
use crate::table::assert_table;

pub(crate) const ROWS: [Row; 2] = [
    // A definition without the `function` keyword.
    Row {
        needle: "local count=",
        kind: SourceUnitKind::Function,
        name: Some("build"),
        span: LineSpan { start: 3, end: 6 },
        text: "build() {\n  local count=\"$1\"\n  echo \"$((count + 1))\"\n}",
    },
    // A definition with it: the optional keyword opens the returned text. The
    // cross-cutting rules resolve this same declaration, so the fixture states
    // it once and the table names it.
    BASH.target,
];

#[test]
fn recognized_declaration_table() {
    assert_table(&BASH, &ROWS);
}
