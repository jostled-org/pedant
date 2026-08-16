//! What one bound parse session answers about the source it was built from.
//!
//! A submodule of `tests/enclosing_unit.rs`, reached through a `#[path]`
//! attribute. One source per grammar, and the declarations each session must
//! name; [`session_probe`](crate::session_probe) owns the model these are
//! written in and the assertions that read them.
//!
//! Each source states two callables with the same name at different
//! declarations and one callable nested inside another, so "narrowest" and
//! "distinct identity" are both written down rather than inferred. Each also
//! holds exactly one `é`, which fixes the byte column the anchor reports and
//! gives the mid-code-point rejection a real offset to land on.

use pedant_syntax::{SourceUnitKind, SyntaxLanguage};

use crate::fixture_support::{assert_covered, tree_sitter_languages};
use crate::session_probe::{
    Anchored, Probe, SessionCase, assert_disabled_grammars_bind_nothing,
    assert_rust_binds_no_session, assert_session_case,
};

// ---------------------------------------------------------------------------
// Per-language sources and expectations
// ---------------------------------------------------------------------------

#[cfg(feature = "ts-python")]
const PYTHON_SOURCE: &str = concat!(
    "import socket\n",                  // 1
    "\n",                               // 2
    "def handle():\n",                  // 3
    "    def handle():\n",              // 4
    "        token = \"py-é-inner\"\n", // 5
    "    return handle\n",              // 6
    "\n",                               // 7
    "\n",                               // 8
    "class Worker:\n",                  // 9
    "    def handle(self):\n",          // 10
    "        token = \"py-outer\"\n",   // 11
);

#[cfg(feature = "ts-javascript")]
const JAVASCRIPT_SOURCE: &str = concat!(
    "const http = require('http');\n",     // 1
    "\n",                                  // 2
    "function handle() {\n",               // 3
    "  function handle() {\n",             // 4
    "    const token = \"js-é-inner\";\n", // 5
    "  }\n",                               // 6
    "  return handle;\n",                  // 7
    "}\n",                                 // 8
    "\n",                                  // 9
    "class Worker {\n",                    // 10
    "  handle() {\n",                      // 11
    "    const token = \"js-outer\";\n",   // 12
    "  }\n",                               // 13
    "}\n",                                 // 14
);

#[cfg(feature = "ts-typescript")]
const TYPESCRIPT_SOURCE: &str = concat!(
    "import * as http from 'http';\n",             // 1
    "\n",                                          // 2
    "function handle(): void {\n",                 // 3
    "  function handle(): void {\n",               // 4
    "    const token: string = \"ts-é-inner\";\n", // 5
    "  }\n",                                       // 6
    "  handle();\n",                               // 7
    "}\n",                                         // 8
    "\n",                                          // 9
    "class Worker {\n",                            // 10
    "  handle(): void {\n",                        // 11
    "    const token: string = \"ts-outer\";\n",   // 12
    "  }\n",                                       // 13
    "}\n",                                         // 14
);

#[cfg(feature = "ts-typescript")]
const TSX_SOURCE: &str = concat!(
    "import * as http from 'http';\n",      // 1
    "\n",                                   // 2
    "function Panel() {\n",                 // 3
    "  function Panel() {\n",               // 4
    "    const token = \"tsx-é-inner\";\n", // 5
    "    return <b>{token}</b>;\n",         // 6
    "  }\n",                                // 7
    "  return <Panel />;\n",                // 8
    "}\n",                                  // 9
    "\n",                                   // 10
    "class Worker {\n",                     // 11
    "  render() {\n",                       // 12
    "    const token = \"tsx-outer\";\n",   // 13
    "    return <i>{token}</i>;\n",         // 14
    "  }\n",                                // 15
    "}\n",                                  // 16
);

#[cfg(feature = "ts-go")]
const GO_SOURCE: &str = concat!(
    "package main\n",                // 1
    "\n",                            // 2
    "import \"net\"\n",              // 3
    "\n",                            // 4
    "func handle() {\n",             // 5
    "\trun := func() {\n",           // 6
    "\t\ttoken := \"go-é-inner\"\n", // 7
    "\t\t_ = token\n",               // 8
    "\t}\n",                         // 9
    "\trun()\n",                     // 10
    "}\n",                           // 11
    "\n",                            // 12
    "type Worker struct {\n",        // 13
    "\tid int\n",                    // 14
    "}\n",                           // 15
    "\n",                            // 16
    "func (w Worker) handle() {\n",  // 17
    "\ttoken := \"go-outer\"\n",     // 18
    "\t_ = token\n",                 // 19
    "}\n",                           // 20
);

#[cfg(feature = "ts-bash")]
const BASH_SOURCE: &str = concat!(
    "curl https://example.test/root\n", // 1
    "\n",                               // 2
    "handle() {\n",                     // 3
    "  inner() {\n",                    // 4
    "    token=\"sh-é-inner\"\n",       // 5
    "  }\n",                            // 6
    "  inner\n",                        // 7
    "}\n",                              // 8
    "\n",                               // 9
    "function handle {\n",              // 10
    "  token=\"sh-outer\"\n",           // 11
    "}\n",                              // 12
);

#[cfg(feature = "ts-python")]
const PYTHON_CASE: SessionCase = SessionCase {
    language: SyntaxLanguage::Python,
    source: PYTHON_SOURCE,
    code_point_owner: Anchored {
        kind: SourceUnitKind::Function,
        name: "handle",
        line: 4,
        column: 5,
    },
    probes: &[
        Probe {
            needle: "import socket",
            owner: None,
        },
        Probe {
            needle: "py-outer",
            owner: Some(Anchored {
                kind: SourceUnitKind::Method,
                name: "handle",
                line: 10,
                column: 5,
            }),
        },
        Probe {
            needle: "class Worker",
            owner: Some(Anchored {
                kind: SourceUnitKind::Class,
                name: "Worker",
                line: 9,
                column: 1,
            }),
        },
    ],
    broken: "def handle(:\n    token = \"broken\"\n",
    broken_needle: "broken",
};

#[cfg(feature = "ts-javascript")]
const JAVASCRIPT_CASE: SessionCase = SessionCase {
    language: SyntaxLanguage::JavaScript,
    source: JAVASCRIPT_SOURCE,
    code_point_owner: Anchored {
        kind: SourceUnitKind::Function,
        name: "handle",
        line: 4,
        column: 3,
    },
    probes: &[
        Probe {
            needle: "require('http')",
            owner: None,
        },
        Probe {
            needle: "js-outer",
            owner: Some(Anchored {
                kind: SourceUnitKind::Method,
                name: "handle",
                line: 11,
                column: 3,
            }),
        },
        Probe {
            needle: "class Worker",
            owner: Some(Anchored {
                kind: SourceUnitKind::Class,
                name: "Worker",
                line: 10,
                column: 1,
            }),
        },
    ],
    broken: "function handle( {\n  const token = \"broken\";\n",
    broken_needle: "broken",
};

#[cfg(feature = "ts-typescript")]
const TYPESCRIPT_CASE: SessionCase = SessionCase {
    language: SyntaxLanguage::TypeScript,
    source: TYPESCRIPT_SOURCE,
    code_point_owner: Anchored {
        kind: SourceUnitKind::Function,
        name: "handle",
        line: 4,
        column: 3,
    },
    probes: &[
        Probe {
            needle: "import * as http",
            owner: None,
        },
        Probe {
            needle: "ts-outer",
            owner: Some(Anchored {
                kind: SourceUnitKind::Method,
                name: "handle",
                line: 11,
                column: 3,
            }),
        },
        Probe {
            needle: "class Worker",
            owner: Some(Anchored {
                kind: SourceUnitKind::Class,
                name: "Worker",
                line: 10,
                column: 1,
            }),
        },
    ],
    broken: "function handle( {\n  const token: string = \"broken\";\n",
    broken_needle: "broken",
};

#[cfg(feature = "ts-typescript")]
const TSX_CASE: SessionCase = SessionCase {
    language: SyntaxLanguage::Tsx,
    source: TSX_SOURCE,
    code_point_owner: Anchored {
        kind: SourceUnitKind::Function,
        name: "Panel",
        line: 4,
        column: 3,
    },
    probes: &[
        Probe {
            needle: "import * as http",
            owner: None,
        },
        Probe {
            needle: "tsx-outer",
            owner: Some(Anchored {
                kind: SourceUnitKind::Method,
                name: "render",
                line: 12,
                column: 3,
            }),
        },
        Probe {
            needle: "class Worker",
            owner: Some(Anchored {
                kind: SourceUnitKind::Class,
                name: "Worker",
                line: 11,
                column: 1,
            }),
        },
    ],
    broken: "function Panel( {\n  const token = \"broken\";\n",
    broken_needle: "broken",
};

#[cfg(feature = "ts-go")]
const GO_CASE: SessionCase = SessionCase {
    language: SyntaxLanguage::Go,
    source: GO_SOURCE,
    code_point_owner: Anchored {
        kind: SourceUnitKind::Function,
        name: "handle",
        line: 5,
        column: 1,
    },
    probes: &[
        Probe {
            needle: "import \"net\"",
            owner: None,
        },
        Probe {
            needle: "go-outer",
            owner: Some(Anchored {
                kind: SourceUnitKind::Method,
                name: "handle",
                line: 17,
                column: 1,
            }),
        },
        Probe {
            needle: "id int",
            owner: Some(Anchored {
                kind: SourceUnitKind::Struct,
                name: "Worker",
                line: 13,
                column: 1,
            }),
        },
    ],
    broken: "package main\n\nfunc handle( {\n\ttoken := \"broken\"\n",
    broken_needle: "broken",
};

#[cfg(feature = "ts-bash")]
const BASH_CASE: SessionCase = SessionCase {
    language: SyntaxLanguage::Bash,
    source: BASH_SOURCE,
    code_point_owner: Anchored {
        kind: SourceUnitKind::Function,
        name: "inner",
        line: 4,
        column: 3,
    },
    probes: &[
        Probe {
            needle: "curl",
            owner: None,
        },
        Probe {
            needle: "inner\n",
            owner: Some(Anchored {
                kind: SourceUnitKind::Function,
                name: "handle",
                line: 3,
                column: 1,
            }),
        },
        Probe {
            needle: "sh-outer",
            owner: Some(Anchored {
                kind: SourceUnitKind::Function,
                name: "handle",
                line: 10,
                column: 1,
            }),
        },
    ],
    broken: "handle() {\n  token=\"broken\"\n",
    broken_needle: "broken",
};

/// Every session case this build links a grammar for.
///
/// One array with a `cfg` per element, so a disabled grammar removes its case
/// at compile time and the length the coverage guard compares is the feature
/// set itself.
fn enabled_cases() -> Box<[SessionCase]> {
    [
        #[cfg(feature = "ts-python")]
        PYTHON_CASE,
        #[cfg(feature = "ts-javascript")]
        JAVASCRIPT_CASE,
        #[cfg(feature = "ts-typescript")]
        TYPESCRIPT_CASE,
        #[cfg(feature = "ts-typescript")]
        TSX_CASE,
        #[cfg(feature = "ts-go")]
        GO_CASE,
        #[cfg(feature = "ts-bash")]
        BASH_CASE,
    ]
    .into_iter()
    .collect()
}

/// 4.T1 (Invariants 4, 5, and 9): one bound session answers every declaration
/// question about the source it parsed, at exact one-based UTF-8 byte
/// positions, and refuses every unaddressable or error-bearing location.
#[test]
fn parsed_syntax_anchor_uses_bound_tree_and_exact_byte_location() {
    let mut reached = 0_usize;
    for case in enabled_cases().iter() {
        assert_session_case(case);
        reached += 1;
    }
    assert_covered(
        reached,
        tree_sitter_languages(),
        "tree-sitter parse session",
    );

    assert_rust_binds_no_session();
    assert_disabled_grammars_bind_nothing();
}
