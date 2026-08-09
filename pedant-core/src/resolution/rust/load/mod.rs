//! Manifest traversal that turns a repository root into a project index.

mod dependency;
mod entry;
mod graph;
mod package;
mod target;

pub(super) use graph::load_project;
