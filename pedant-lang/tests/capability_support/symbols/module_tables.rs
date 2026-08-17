//! Sources that put a capability at module scope, with callables around it.
//!
//! A projection that hoisted the module's capability into a neighboring
//! callable disagrees with these tables. [`cases`](super::cases) asserts them.
//!
//! Each family list below says where that source's families reach a callable.
//! A family written only at module scope is listed as unowned, and that is the
//! claim: no callable beside it inherits the capability.

use pedant_types::{Capability, CapabilitySymbolKind, FindingOrigin};

use super::model::{Family, Row, owned_by};
// Only the Go source states its module-scope capability as a string literal;
// every other backend states both of its rows outright.
#[cfg(feature = "ts-go")]
use super::model::literal_row;

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

/// Python writes both its imports as the same family: one at module scope, one
/// inside `beta`, so the family reaches a callable here and the row table alone
/// carries which of the two did.
#[cfg(feature = "ts-python")]
pub(crate) const PYTHON_MODULE_FAMILIES: [Family; 1] = [Family {
    name: "import",
    owned: true,
}];

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

/// The ES `import` is module-level by grammar; the `require` call sits inside
/// `beta`, so the two families split cleanly across the boundary this case is
/// about.
#[cfg(any(feature = "ts-javascript", feature = "ts-typescript"))]
pub(crate) const JS_MODULE_FAMILIES: [Family; 2] = [
    Family {
        name: "import",
        owned: false,
    },
    Family {
        name: "require",
        owned: true,
    },
];

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

/// A Go import declaration is module-level by grammar; the endpoint literal
/// sits inside `beta`.
#[cfg(feature = "ts-go")]
pub(crate) const GO_MODULE_FAMILIES: [Family; 2] = [
    Family {
        name: "import",
        owned: false,
    },
    Family {
        name: "string-literal",
        owned: true,
    },
];

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

/// A bash command can sit inside a function — the family case proves that — so
/// `command` is listed unowned here because this source writes its `curl` at
/// module scope on purpose, and no function below it may claim the capability.
#[cfg(feature = "ts-bash")]
pub(crate) const BASH_MODULE_FAMILIES: [Family; 2] = [
    Family {
        name: "command",
        owned: false,
    },
    Family {
        name: "export",
        owned: true,
    },
];

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
