//! Sources that put a capability at module scope, with callables around it.
//!
//! A projection that hoisted the module's capability into a neighboring
//! callable disagrees with these tables.
//! [`symbol_cases`](crate::symbol_cases) asserts them.

use pedant_types::{Capability, CapabilitySymbolKind, FindingOrigin};

use crate::symbol_model::{Row, owned_by};
// Only the Go source states its module-scope capability as a string literal;
// every other backend states both of its rows outright.
#[cfg(feature = "ts-go")]
use crate::symbol_model::literal_row;

#[cfg(feature = "ts-python")]
pub(crate) const PYTHON_MODULE_SOURCE: &str = concat!(
    "import socket\n",         // 1
    "\n",                      // 2
    "def alpha():\n",          // 3
    "    pass\n",              // 4
    "\n",                      // 5
    "def beta():\n",           // 6
    "    import subprocess\n", // 7
    "\n",                      // 8
    "def gamma():\n",          // 9
    "    pass\n",              // 10
);

#[cfg(feature = "ts-python")]
pub(crate) const PYTHON_MODULE_ROWS: [Row; 2] = [
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
        line: 7,
        column: 5,
        origin: FindingOrigin::Import,
        family: "import",
        owner: owned_by(CapabilitySymbolKind::Function, "beta", 6, 1),
    },
];

#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
pub(crate) const JAVASCRIPT_MODULE_SOURCE: &str = concat!(
    "import axios from 'axios';\n",             // 1
    "\n",                                       // 2
    "function alpha() {}\n",                    // 3
    "\n",                                       // 4
    "function beta() {\n",                      // 5
    "  const cp = require('child_process');\n", // 6
    "}\n",                                      // 7
    "\n",                                       // 8
    "function gamma() {}\n",                    // 9
);

/// The flat sequence both JavaScript-family module sources produce.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
pub(crate) const JS_MODULE_ROWS: [Row; 2] = [
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
        line: 6,
        column: 14,
        origin: FindingOrigin::Import,
        family: "require",
        owner: owned_by(CapabilitySymbolKind::Function, "beta", 5, 1),
    },
];

#[cfg(feature = "ts-go")]
pub(crate) const GO_MODULE_SOURCE: &str = concat!(
    "package main\n",                            // 1
    "\n",                                        // 2
    "import \"net\"\n",                          // 3
    "\n",                                        // 4
    "func alpha() {}\n",                         // 5
    "\n",                                        // 6
    "func beta() {\n",                           // 7
    "\ttoken := \"https://api.example.test\"\n", // 8
    "\t_ = token\n",                             // 9
    "}\n",                                       // 10
    "\n",                                        // 11
    "func gamma() {}\n",                         // 12
);

#[cfg(feature = "ts-go")]
pub(crate) const GO_MODULE_ROWS: [Row; 2] = [
    Row {
        capability: Capability::Network,
        evidence: "net",
        line: 3,
        column: 8,
        origin: FindingOrigin::Import,
        family: "import",
        owner: None,
    },
    literal_row(
        8,
        11,
        "https://api.example.test",
        owned_by(CapabilitySymbolKind::Function, "beta", 7, 1),
    ),
];

#[cfg(feature = "ts-bash")]
pub(crate) const BASH_MODULE_SOURCE: &str = concat!(
    "curl https://example.test/root\n", // 1
    "\n",                               // 2
    "alpha() {\n",                      // 3
    "  echo alpha\n",                   // 4
    "}\n",                              // 5
    "\n",                               // 6
    "beta() {\n",                       // 7
    "  export TOKEN=secret\n",          // 8
    "}\n",                              // 9
    "\n",                               // 10
    "gamma() {\n",                      // 11
    "  echo gamma\n",                   // 12
    "}\n",                              // 13
);

#[cfg(feature = "ts-bash")]
pub(crate) const BASH_MODULE_ROWS: [Row; 2] = [
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
        line: 8,
        column: 3,
        origin: FindingOrigin::CodeSite,
        family: "export",
        owner: owned_by(CapabilitySymbolKind::Function, "beta", 7, 1),
    },
];
