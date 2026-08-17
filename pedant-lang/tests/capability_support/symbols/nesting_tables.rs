//! Sources that declare one name twice and nest one callable inside another.
//!
//! A projection that keyed symbols by name, or that credited the outer
//! declaration, disagrees with these tables. [`cases`](super::cases) asserts
//! them.

use pedant_types::CapabilitySymbolKind;

use super::model::{Family, Row, literal_row, owned_by};

/// The one family every nesting source states: a URL in a string literal, and
/// every one of them inside a callable.
///
/// Nesting is the subject here, so each source states one family and states it
/// several times over, at different depths and under repeated names.
pub(crate) const NESTED_FAMILIES: [Family; 1] = [Family {
    name: "string-literal",
    owned: true,
}];

#[cfg(feature = "ts-python")]
pub(crate) const PYTHON_NESTED_SOURCE: &str = concat!(
    "def handle():\n",                                   // 1
    "    def handle():\n",                               // 2
    "        token = \"https://inner.example.test\"\n",  // 3
    "    token = \"https://outer.example.test\"\n",      // 4
    "\n",                                                // 5
    "class Worker:\n",                                   // 6
    "    def handle(self):\n",                           // 7
    "        token = \"https://method.example.test\"\n", // 8
);

#[cfg(feature = "ts-python")]
pub(crate) const PYTHON_NESTED_ROWS: [Row; 3] = [
    literal_row(
        3,
        17,
        "https://inner.example.test",
        owned_by(CapabilitySymbolKind::Function, "handle", 2, 5),
    ),
    literal_row(
        4,
        13,
        "https://outer.example.test",
        owned_by(CapabilitySymbolKind::Function, "handle", 1, 1),
    ),
    literal_row(
        8,
        17,
        "https://method.example.test",
        owned_by(CapabilitySymbolKind::Method, "handle", 7, 5),
    ),
];

#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
pub(crate) const JAVASCRIPT_NESTED_SOURCE: &str = concat!(
    "function handle() {\n",                                // 1
    "  function handle() {\n",                              // 2
    "    const token = \"https://inner.example.test\";\n",  // 3
    "  }\n",                                                // 4
    "  const token = \"https://outer.example.test\";\n",    // 5
    "}\n",                                                  // 6
    "\n",                                                   // 7
    "class Worker {\n",                                     // 8
    "  handle() {\n",                                       // 9
    "    const token = \"https://method.example.test\";\n", // 10
    "  }\n",                                                // 11
    "}\n",                                                  // 12
);

/// The flat sequence both JavaScript-family nested sources produce.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
pub(crate) const JS_NESTED_ROWS: [Row; 3] = [
    literal_row(
        3,
        19,
        "https://inner.example.test",
        owned_by(CapabilitySymbolKind::Function, "handle", 2, 3),
    ),
    literal_row(
        5,
        17,
        "https://outer.example.test",
        owned_by(CapabilitySymbolKind::Function, "handle", 1, 1),
    ),
    literal_row(
        10,
        19,
        "https://method.example.test",
        owned_by(CapabilitySymbolKind::Method, "handle", 9, 3),
    ),
];

#[cfg(feature = "ts-go")]
pub(crate) const GO_NESTED_SOURCE: &str = concat!(
    "package main\n",                                 // 1
    "\n",                                             // 2
    "func handle() {\n",                              // 3
    "\trun := func() {\n",                            // 4
    "\t\ttoken := \"https://nested.example.test\"\n", // 5
    "\t\t_ = token\n",                                // 6
    "\t}\n",                                          // 7
    "\trun()\n",                                      // 8
    "}\n",                                            // 9
    "\n",                                             // 10
    "type Worker struct{ id int }\n",                 // 11
    "\n",                                             // 12
    "func (w Worker) handle() {\n",                   // 13
    "\ttoken := \"https://method.example.test\"\n",   // 14
    "\t_ = token\n",                                  // 15
    "}\n",                                            // 16
);

#[cfg(feature = "ts-go")]
pub(crate) const GO_NESTED_ROWS: [Row; 2] = [
    literal_row(
        5,
        12,
        "https://nested.example.test",
        owned_by(CapabilitySymbolKind::Function, "handle", 3, 1),
    ),
    literal_row(
        14,
        11,
        "https://method.example.test",
        owned_by(CapabilitySymbolKind::Method, "handle", 13, 1),
    ),
];

#[cfg(feature = "ts-bash")]
pub(crate) const BASH_NESTED_SOURCE: &str = concat!(
    "handle() {\n",                               // 1
    "  inner() {\n",                              // 2
    "    token=\"https://inner.example.test\"\n", // 3
    "  }\n",                                      // 4
    "  token=\"https://outer.example.test\"\n",   // 5
    "}\n",                                        // 6
    "\n",                                         // 7
    "function handle {\n",                        // 8
    "  token=\"https://second.example.test\"\n",  // 9
    "}\n",                                        // 10
);

#[cfg(feature = "ts-bash")]
pub(crate) const BASH_NESTED_ROWS: [Row; 3] = [
    literal_row(
        3,
        11,
        "https://inner.example.test",
        owned_by(CapabilitySymbolKind::Function, "inner", 2, 3),
    ),
    literal_row(
        5,
        9,
        "https://outer.example.test",
        owned_by(CapabilitySymbolKind::Function, "handle", 1, 1),
    ),
    literal_row(
        9,
        9,
        "https://second.example.test",
        owned_by(CapabilitySymbolKind::Function, "handle", 8, 1),
    ),
];
