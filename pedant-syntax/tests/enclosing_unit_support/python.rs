//! Python backend: recognized declarations, decorated definitions, method
//! precedence inside a class, and the direct-owner rule that separates a
//! method from a function nested in one.

use pedant_syntax::{LineSpan, SourceUnitKind};

use crate::fixtures::{PYTHON, Row};
use crate::table::assert_table;

pub(crate) const ROWS: [Row; 7] = [
    // A decorated class: `decorated_definition` opens the returned text, and
    // the class wins only outside every method its body declares.
    Row {
        needle: "\"\"\"Route table.\"\"\"",
        kind: SourceUnitKind::Class,
        name: Some("Service"),
        span: LineSpan { start: 4, end: 16 },
        text: "@dataclass\nclass Service:\n    \"\"\"Route table.\"\"\"\n\n    @staticmethod\n    def build(count):\n        def scale(step):\n            return step * 2\n        return scale(count) + 1\n\n    def run(self):\n        label = \"héllo\"\n        return label",
    },
    // A decorated method beats the decorated class holding it, and its own
    // decorator opens its text.
    Row {
        needle: "return scale(count) + 1",
        kind: SourceUnitKind::Method,
        name: Some("build"),
        span: LineSpan { start: 8, end: 12 },
        text: "@staticmethod\n    def build(count):\n        def scale(step):\n            return step * 2\n        return scale(count) + 1",
    },
    // A `def` a method body declares: the class is an ancestor but not the
    // owner, so the kind is `Function`.
    Row {
        needle: "return step * 2",
        kind: SourceUnitKind::Function,
        name: Some("scale"),
        span: LineSpan { start: 10, end: 11 },
        text: "def scale(step):\n            return step * 2",
    },
    // The declaration the cross-cutting rules resolve, stated once on the
    // fixture and named here rather than restated.
    PYTHON.target,
    Row {
        needle: "return value",
        kind: SourceUnitKind::Function,
        name: Some("helper"),
        span: LineSpan { start: 19, end: 20 },
        text: "def helper(value):\n    return value",
    },
    // An undecorated class: the bare `class_definition` mapping, reachable
    // only when no decorator owns it.
    Row {
        needle: "entries = []",
        kind: SourceUnitKind::Class,
        name: Some("Registry"),
        span: LineSpan { start: 23, end: 24 },
        text: "class Registry:\n    entries = []",
    },
    // A decorated module-level function: `decorated_definition` resolving to
    // `Function`, not `Method`.
    Row {
        needle: "return key",
        kind: SourceUnitKind::Function,
        name: Some("resolve"),
        span: LineSpan { start: 27, end: 29 },
        text: "@cache\ndef resolve(key):\n    return key",
    },
];

#[test]
fn recognized_declaration_table() {
    assert_table(&PYTHON, &ROWS);
}
