//! Language-agnostic string literal analysis helpers.

mod c_family;
mod evidence;
mod findings;
mod quoted;

pub(crate) use c_family::{scan_go_string_literals, scan_js_string_literals};
pub(crate) use findings::{
    detect_call_sites, detect_string_literal_findings, is_shell_command_boundary,
    matches_module_prefix,
};
pub(crate) use quoted::{CommentStyle, scan_string_literals};
