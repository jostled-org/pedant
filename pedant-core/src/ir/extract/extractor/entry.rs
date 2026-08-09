use syn::visit::Visit;

use crate::ir::facts::FileIr;
use crate::observe::{self, Observation};

use super::IrExtractor;

/// Single-pass AST visitor that populates a [`FileIr`] from a parsed source file.
///
/// When `semantic` is `Some`, a second enrichment pass resolves type aliases
/// and marks `Copy` receivers.
pub fn extract(
    file_path: &str,
    syntax: &syn::File,
    semantic: Option<&crate::ir::semantic::SemanticContext>,
) -> FileIr {
    observe::record(Observation::SiteVisit(file_path));
    let mut extractor = IrExtractor::new(file_path);
    extractor.visit_file(syntax);
    #[cfg(feature = "semantic")]
    {
        let mut ir = extractor.finalize();
        if let Some(ctx) = semantic {
            super::super::enrich::enrich_ir(&mut ir, ctx);
        }
        ir
    }
    #[cfg(not(feature = "semantic"))]
    {
        _ = semantic;
        extractor.finalize()
    }
}
