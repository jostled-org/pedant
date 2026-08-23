//! The temporary Go repositories every Go graph case projects, written out.
//!
//! Each corpus is a real repository the production loader, snapshot walk, and
//! syntactic resolver read; no case mocks a project, a snapshot, or a report.
//! Nothing here runs the Go command, and no module is fetched: the one
//! dependency a corpus resolves is a local replacement inside its own tree, and
//! the one it does not resolve is deliberately external.

use super::corpus::FixtureFile;

/// One main module with three package directories, an internal test context, a
/// local replacement, and an unreplaced external requirement.
///
/// It reaches every Go declaration the graph names, every reference kind a Go
/// report states, a concrete method set, a structural implementation, an
/// interface dispatch, a conversion that is not a call, and a source two
/// package contexts instantiate.
pub const GO_CORPUS: &[FixtureFile] = &[
    (
        "repo/go.mod",
        r#"module example.com/app

go 1.22

require (
	example.com/helper v0.1.0
	github.com/external/pkg v1.4.0
)

replace example.com/helper => ./helper
"#,
    ),
    (
        "repo/app.go",
        r#"package app

import (
	"example.com/app/shapes"
	"example.com/helper"
)

const Limit = 4

var Registry = "app"

type Size int

type Widget struct {
	Name string
}

type Alias = Widget

func (w Widget) Area() int {
	return Limit
}

func Run() int {
	w := Widget{Name: Registry}
	var s shapes.Shape = w
	return w.Area() + s.Area() + int(Size(Limit)) + helper.Assist() + Build()
}
"#,
    ),
    (
        "repo/build.go",
        r#"package app

func Build() int {
	return 1
}
"#,
    ),
    (
        "repo/app_test.go",
        r#"package app

func measured() int {
	return Run()
}
"#,
    ),
    (
        "repo/shapes/shapes.go",
        r#"package shapes

type Shape interface {
	Area() int
}
"#,
    ),
    (
        "repo/helper/go.mod",
        r#"module example.com/helper

go 1.22
"#,
    ),
    (
        "repo/helper/assist.go",
        r#"package helper

func Assist() int {
	return 2
}
"#,
    ),
];

/// One main module whose sole package directory has a same-package test file.
///
/// The two contexts of that directory instantiate the same production source,
/// which is what a unit-qualified file node is for.
pub const GO_SHARED_SOURCE_CORPUS: &[FixtureFile] = &[
    (
        "repo/go.mod",
        r#"module example.com/shared

go 1.22
"#,
    ),
    (
        "repo/value.go",
        r#"package shared

func Value() int {
	return 3
}
"#,
    ),
    (
        "repo/value_test.go",
        r#"package shared

func doubled() int {
	return Value() * 2
}
"#,
    ),
];

/// One main module with no requirement, no test file, and one declaration.
///
/// The smallest repository the loader admits, so a lowered ceiling refuses over
/// a corpus whose every record is countable by hand.
pub const GO_MINIMAL_CORPUS: &[FixtureFile] = &[
    (
        "repo/go.mod",
        r#"module example.com/tiny

go 1.22
"#,
    ),
    (
        "repo/tiny.go",
        r#"package tiny

func Only() int {
	return 1
}
"#,
    ),
];
