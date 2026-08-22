//! The one Go source every fact claim is read from, and the extraction it is
//! read through.
//!
//! A submodule of `tests/enclosing_unit.rs`, reached through a `#[path]`
//! attribute. The completeness claims, the type-evidence claims, and the
//! ceiling claims all read this fixture, so it is stated once rather than once
//! per module: a claim written against its own source proves nothing about the
//! inventory another claim reads.

use pedant_syntax::SyntaxLanguage;
use pedant_syntax::go::{GoFactError, GoFactLimits, GoFileFacts};
use pedant_syntax::tree_sitter::parse_bound;

/// One Go source holding every fact family the inventory claims.
///
/// Line numbers are written beside each line because every expectation read
/// from it names a zero-based line, and a source whose lines are counted by
/// hand is one an editor can silently renumber.
pub(crate) const FACT_SOURCE: &str = concat!(
    "//go:build linux && cgo\n",             // 0
    "// +build linux,cgo\n",                 // 1
    "\n",                                    // 2
    "package widget\n",                      // 3
    "\n",                                    // 4
    "import (\n",                            // 5
    "\t\"fmt\"\n",                           // 6
    "\talias \"net/http\"\n",                // 7
    "\t_ \"embed\"\n",                       // 8
    "\t. \"strings\"\n",                     // 9
    ")\n",                                   // 10
    "\n",                                    // 11
    "const Limit = 10\n",                    // 12
    "\n",                                    // 13
    "var Shared int\n",                      // 14
    "\n",                                    // 15
    "type Config struct {\n",                // 16
    "\tRetries int\n",                       // 17
    "\tfmt.Stringer\n",                      // 18
    "}\n",                                   // 19
    "\n",                                    // 20
    "type Runner interface {\n",             // 21
    "\tRun(n int) error\n",                  // 22
    "}\n",                                   // 23
    "\n",                                    // 24
    "type Handle Config\n",                  // 25
    "\n",                                    // 26
    "type Alias = Config\n",                 // 27
    "\n",                                    // 28
    "func build(count int) (sum int) {\n",   // 29
    "\tlocal := count\n",                    // 30
    "\t{\n",                                 // 31
    "\t\tvar inner int = local\n",           // 32
    "\t\tsum = inner\n",                     // 33
    "\t}\n",                                 // 34
    "\tfmt.Println(sum)\n",                  // 35
    "\treturn sum\n",                        // 36
    "}\n",                                   // 37
    "\n",                                    // 38
    "func (c *Config) Run(n int) error {\n", // 39
    "\tlabel := \"gö\"\n",                   // 40
    "\t_ = label\n",                         // 41
    "\treturn nil\n",                        // 42
    "}\n",                                   // 43
    "\n",                                    // 44
    "func shapes(raw int) {\n",              // 45
    "\tvalue := Config{}\n",                 // 46
    "\tpointed := &Config{}\n",              // 47
    "\tforeign := alias.Client{}\n",         // 48
    "\tcalled := build(raw)\n",              // 49
    "\tremote := alias.Get(\"\")\n",         // 50
    "\tconverted := Handle(value)\n",        // 51
    "\tmapped := map[string]int{}\n",        // 52
    "\tsliced := []Config{}\n",              // 53
    "\tpiped := (chan int)(nil)\n",          // 54
    "\ttaken := &build(raw)\n",              // 55
    "\tfirst, second := build(raw), raw\n",  // 56
    "\tblocked := <-piped\n",                // 57
    "}\n",                                   // 58
    "\n",                                    // 59
    "func spawn() *Config {\n",              // 60
    "\treturn &Config{}\n",                  // 61
    "}\n",                                   // 62
    "\n",                                    // 63
    "func fetch() alias.Client {\n",         // 64
    "\treturn alias.Client{}\n",             // 65
    "}\n",                                   // 66
    "\n",                                    // 67
    "func pair() (int, error) {\n",          // 68
    "\treturn 0, nil\n",                     // 69
    "}\n",                                   // 70
    "\n",                                    // 71
    "func table() map[string]int {\n",       // 72
    "\treturn nil\n",                        // 73
    "}\n",                                   // 74
    "\n",                                    // 75
    "func boxed() *[]Config {\n",            // 76
    "\treturn nil\n",                        // 77
    "}\n",                                   // 78
    "\n",                                    // 79
    "func serve(client alias.Client) {\n",   // 80
    "\tvar held Config\n",                   // 81
    "\tvar linked *alias.Client\n",          // 82
    "\t_ = held\n",                          // 83
    "\t_ = linked\n",                        // 84
    "\t_ = client\n",                        // 85
    "}\n",                                   // 86
    "\n",                                    // 87
    "type Embedder struct {\n",              // 88
    "\tConfig\n",                            // 89
    "\t*Handle\n",                           // 90
    "}\n",                                   // 91
);

/// Build the inventory every claim is read from.
pub(crate) fn facts(source: &str, limits: GoFactLimits) -> Result<GoFileFacts<'_>, GoFactError> {
    let parsed = parse_bound(source, SyntaxLanguage::Go).expect("the Go grammar parses the source");
    parsed.go_file_facts(limits)
}

/// The inventory of [`FACT_SOURCE`], with no ceiling in the way.
pub(crate) fn complete_facts() -> GoFileFacts<'static> {
    facts(FACT_SOURCE, GoFactLimits::UNBOUNDED).expect("an unbounded inventory")
}
