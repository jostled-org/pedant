//! One source per backend, carrying every detection family that backend covers.
//!
//! The written-down flat sequence for each, in detection order.
//! [`cases`](super::cases) asserts these tables and [`model`](super::model)
//! states what asserting one means.

use pedant_types::{Capability, CapabilitySymbolKind, FindingOrigin};

use super::model::{Family, Row, literal_row, owned_by};

#[cfg(feature = "ts-python")]
pub(crate) const PYTHON_FAMILY_SOURCE: &str = concat!(
    "import socket\n",                               // 1
    "\n",                                            // 2
    "def fetch(url):\n",                             // 3
    "    import subprocess\n",                       // 4
    "    handle = open(url)\n",                      // 5
    "    return handle\n",                           // 6
    "\n",                                            // 7
    "\n",                                            // 8
    "class Client:\n",                               // 9
    "    def token(self):\n",                        // 10
    "        return \"https://api.example.test\"\n", // 11
);

#[cfg(feature = "ts-python")]
pub(crate) const PYTHON_FAMILIES: [Family; 3] = [
    Family {
        name: "import",
        owned: true,
    },
    Family {
        name: "call",
        owned: true,
    },
    Family {
        name: "string-literal",
        owned: true,
    },
];

#[cfg(feature = "ts-python")]
pub(crate) const PYTHON_FAMILY_ROWS: [Row; 4] = [
    Row {
        capability: Capability::Network,
        evidence: "socket",
        line: 1,
        column: 1,
        origin: FindingOrigin::Import,
        family: "import",
        owner: None,
    },
    Row {
        capability: Capability::ProcessExec,
        evidence: "subprocess",
        line: 4,
        column: 5,
        origin: FindingOrigin::Import,
        family: "import",
        owner: owned_by(CapabilitySymbolKind::Function, "fetch", 3, 1),
    },
    Row {
        capability: Capability::FileRead,
        evidence: "open()",
        line: 5,
        column: 14,
        origin: FindingOrigin::CodeSite,
        family: "call",
        owner: owned_by(CapabilitySymbolKind::Function, "fetch", 3, 1),
    },
    literal_row(
        11,
        16,
        "https://api.example.test",
        owned_by(CapabilitySymbolKind::Method, "token", 10, 5),
    ),
];

#[cfg(feature = "ts-javascript")]
pub(crate) const JAVASCRIPT_FAMILY_SOURCE: &str = concat!(
    "import axios from 'axios';\n",                     // 1
    "\n",                                               // 2
    "function fetchAll(url) {\n",                       // 3
    "  const cp = require('child_process');\n",         // 4
    "  return fetch(url);\n",                           // 5
    "}\n",                                              // 6
    "\n",                                               // 7
    "class Client {\n",                                 // 8
    "  token() {\n",                                    // 9
    "    const key = process.env.TOKEN;\n",             // 10
    "    return \"https://api.example.test\" + key;\n", // 11
    "  }\n",                                            // 12
    "}\n",                                              // 13
);

#[cfg(feature = "ts-typescript")]
pub(crate) const TYPESCRIPT_FAMILY_SOURCE: &str = concat!(
    "import axios from 'axios';\n",                     // 1
    "\n",                                               // 2
    "function fetchAll(url: string) {\n",               // 3
    "  const cp = require('child_process');\n",         // 4
    "  return fetch(url);\n",                           // 5
    "}\n",                                              // 6
    "\n",                                               // 7
    "class Client {\n",                                 // 8
    "  token(): string {\n",                            // 9
    "    const key = process.env.TOKEN;\n",             // 10
    "    return \"https://api.example.test\" + key;\n", // 11
    "  }\n",                                            // 12
    "}\n",                                              // 13
);

/// The detection families the JavaScript and TypeScript backends share.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
pub(crate) const JS_FAMILIES: [Family; 5] = [
    Family {
        name: "import",
        owned: false,
    },
    Family {
        name: "require",
        owned: true,
    },
    Family {
        name: "call",
        owned: true,
    },
    Family {
        name: "member",
        owned: true,
    },
    Family {
        name: "string-literal",
        owned: true,
    },
];

/// The flat sequence both JavaScript-family sources produce.
///
/// The two sources differ only in type annotations, which open no declaration
/// and move no byte on any line a row names, so one table serves both rather
/// than two that could drift.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
pub(crate) const JS_FAMILY_ROWS: [Row; 5] = [
    Row {
        capability: Capability::Network,
        evidence: "axios",
        line: 1,
        column: 1,
        origin: FindingOrigin::Import,
        family: "import",
        owner: None,
    },
    Row {
        capability: Capability::ProcessExec,
        evidence: "child_process",
        line: 4,
        column: 14,
        origin: FindingOrigin::Import,
        family: "require",
        owner: owned_by(CapabilitySymbolKind::Function, "fetchAll", 3, 1),
    },
    Row {
        capability: Capability::Network,
        evidence: "fetch",
        line: 5,
        column: 10,
        origin: FindingOrigin::CodeSite,
        family: "call",
        owner: owned_by(CapabilitySymbolKind::Function, "fetchAll", 3, 1),
    },
    Row {
        capability: Capability::EnvAccess,
        evidence: "process.env",
        line: 10,
        column: 17,
        origin: FindingOrigin::CodeSite,
        family: "member",
        owner: owned_by(CapabilitySymbolKind::Method, "token", 9, 3),
    },
    literal_row(
        11,
        12,
        "https://api.example.test",
        owned_by(CapabilitySymbolKind::Method, "token", 9, 3),
    ),
];

#[cfg(feature = "ts-go")]
pub(crate) const GO_FAMILY_SOURCE: &str = concat!(
    "package main\n",                          // 1
    "\n",                                      // 2
    "import \"os/exec\"\n",                    // 3
    "\n",                                      // 4
    "func run(name string) error {\n",         // 5
    "\tcmd := exec.Command(name)\n",           // 6
    "\treturn cmd.Run()\n",                    // 7
    "}\n",                                     // 8
    "\n",                                      // 9
    "type Client struct{ id int }\n",          // 10
    "\n",                                      // 11
    "func (c Client) endpoint() string {\n",   // 12
    "\treturn \"https://api.example.test\"\n", // 13
    "}\n",                                     // 14
);

#[cfg(feature = "ts-go")]
pub(crate) const GO_FAMILIES: [Family; 3] = [
    Family {
        name: "import",
        owned: false,
    },
    Family {
        name: "qualified-call",
        owned: true,
    },
    Family {
        name: "string-literal",
        owned: true,
    },
];

#[cfg(feature = "ts-go")]
pub(crate) const GO_FAMILY_ROWS: [Row; 3] = [
    Row {
        capability: Capability::ProcessExec,
        evidence: "os/exec",
        line: 3,
        column: 8,
        origin: FindingOrigin::Import,
        family: "import",
        owner: None,
    },
    Row {
        capability: Capability::ProcessExec,
        evidence: "exec.Command",
        line: 6,
        column: 9,
        origin: FindingOrigin::CodeSite,
        family: "qualified-call",
        owner: owned_by(CapabilitySymbolKind::Function, "run", 5, 1),
    },
    literal_row(
        13,
        9,
        "https://api.example.test",
        owned_by(CapabilitySymbolKind::Method, "endpoint", 12, 1),
    ),
];

#[cfg(feature = "ts-bash")]
pub(crate) const BASH_FAMILY_SOURCE: &str = concat!(
    "curl https://example.test/root\n",          // 1
    "\n",                                        // 2
    "deploy() {\n",                              // 3
    "  export TOKEN=secret\n",                   // 4
    "  rsync -a ./dist remote:/srv\n",           // 5
    "  endpoint=\"https://api.example.test\"\n", // 6
    "}\n",                                       // 7
);

#[cfg(feature = "ts-bash")]
pub(crate) const BASH_FAMILIES: [Family; 3] = [
    Family {
        name: "command",
        owned: true,
    },
    Family {
        name: "export",
        owned: true,
    },
    Family {
        name: "string-literal",
        owned: true,
    },
];

#[cfg(feature = "ts-bash")]
pub(crate) const BASH_FAMILY_ROWS: [Row; 4] = [
    Row {
        capability: Capability::Network,
        evidence: "curl",
        line: 1,
        column: 1,
        origin: FindingOrigin::CodeSite,
        family: "command",
        owner: None,
    },
    Row {
        capability: Capability::EnvAccess,
        evidence: "export",
        line: 4,
        column: 3,
        origin: FindingOrigin::CodeSite,
        family: "export",
        owner: owned_by(CapabilitySymbolKind::Function, "deploy", 3, 1),
    },
    Row {
        capability: Capability::Network,
        evidence: "rsync",
        line: 5,
        column: 3,
        origin: FindingOrigin::CodeSite,
        family: "command",
        owner: owned_by(CapabilitySymbolKind::Function, "deploy", 3, 1),
    },
    literal_row(
        6,
        12,
        "https://api.example.test",
        owned_by(CapabilitySymbolKind::Function, "deploy", 3, 1),
    ),
];
