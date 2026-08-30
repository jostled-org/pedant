//! The products this workspace installs, written down.
//!
//! Stated rather than discovered, for the reason every model beside it is: a
//! set read off the workspace agrees with whatever the workspace happens to
//! hold, so it could reject neither a fourth product an operator is never told
//! to install nor a third that quietly stopped being published.
//!
//! Beside its reader rather than inside it, because the two are different
//! subjects. A row here is one binary an operator installs; the rows
//! [`super::operator_documentation`] reads out of that product's own sources
//! are the questions one of those binaries answers. Nothing relates the two
//! but the document that states both, and a file holding them together said so
//! only by sitting them side by side.

/// One installed product, and the manifest that publishes it.
pub(crate) struct Product {
    /// The crate an operator installs.
    pub(crate) package: &'static str,
    /// Its manifest, repository-relative.
    pub(crate) manifest: &'static str,
    /// A word its published description must carry, which is what tells the
    /// three apart in a registry listing.
    pub(crate) role: &'static str,
}

/// The three products this workspace installs.
///
/// Three binaries, three questions. A README that told an operator to install
/// two of them would leave the third unreachable, and one that described a
/// product by another's role would send a reader to the wrong binary.
pub(crate) static PRODUCTS: [Product; 3] = [
    Product {
        package: "pedant",
        manifest: "pedant/Cargo.toml",
        role: "linter",
    },
    Product {
        package: "pedant-mcp",
        manifest: "pedant-mcp/Cargo.toml",
        role: "MCP",
    },
    Product {
        package: "pedant-snippet",
        manifest: "pedant-snippet/Cargo.toml",
        role: "code intelligence",
    },
];
