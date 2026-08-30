//! The feature selection a mixed six-language claim needs, stated once.
//!
//! Three support trees make the same claim about the same repository — the index
//! cases, the navigation cases, and the transport journeys — and none of them is
//! answerable by a build that links four of the six languages or one of the two
//! graph producers. The gate is written here rather than in each tree, because
//! two copies of a feature list are two chances for a profile to compile one
//! tree and skip the other.

/// Compile each item only where the whole closed language and graph selection
/// is linked.
///
/// The one place the feature list is written. Both forms below expand through
/// it, so a language added to the closed table is added here and nowhere else.
///
/// All eight are named, including the two the graph features already forward
/// to. `graph-rust = ["lang-rust", ...]` and `graph-go = ["lang-go", ...]` are
/// statements in the manifest rather than in this gate, so a build that stopped
/// forwarding either edge would compile the whole six-language journey tree
/// against five grammars and say nothing. The gate claims to state the closed
/// selection, so it states it.
macro_rules! complete_profile {
    ($($item:item)*) => {
        $(
            #[cfg(all(
                feature = "lang-rust",
                feature = "lang-go",
                feature = "lang-javascript",
                feature = "lang-typescript",
                feature = "lang-python",
                feature = "lang-bash",
                feature = "graph-rust",
                feature = "graph-go"
            ))]
            $item
        )*
    };
}

/// Compile each named module of the invoking directory under that gate.
macro_rules! complete_profile_modules {
    ($($module:ident),+ $(,)?) => {
        $crate::profile_gate::complete_profile! {
            $(pub(crate) mod $module;)+
        }
    };
}

/// Compile each named module from its explicit path under that gate.
///
/// The root declares its support modules with `#[path]`, because cargo would
/// otherwise look for them in a directory named after the root — which pedant's
/// `conflicting-module-root` rule rejects beside a `tests/*.rs` file cargo is
/// already building as an executable.
macro_rules! complete_profile_path_modules {
    ($($path:literal => $module:ident),+ $(,)?) => {
        $crate::profile_gate::complete_profile! {
            $(#[path = $path] pub(crate) mod $module;)+
        }
    };
}

pub(crate) use {complete_profile, complete_profile_modules, complete_profile_path_modules};
