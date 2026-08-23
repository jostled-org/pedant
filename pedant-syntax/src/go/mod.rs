//! Structured Go grammar facts, extracted once from a bound parse session.
//!
//! One inventory answers every structured question about a Go source:
//! [`GoFileFacts`] holds the package clause, the build predicates, the imports,
//! the declarations, the signature terms those declarations state, the reference
//! sites, the lexical scopes, and the bound names, in source order and bound to
//! the exact bytes they were read from.
//! Capability attribution and Go resolution both read it, so neither owns a
//! grammar mapping the other could drift from.
//!
//! Extraction is one checked walk of a tree that was already parsed:
//! [`ParsedSyntax::go_file_facts`](crate::tree_sitter::ParsedSyntax::go_file_facts)
//! parses nothing, reads no file, and runs no process. Both ceilings in
//! [`GoFactLimits`] refuse before the state they would pay for is retained, so
//! a lowered ceiling returns a [`GoFactError`] and no inventory rather than a
//! truncated one.

mod binding;
mod condition;
mod context;
mod declaration;
mod error;
mod facts;
mod frame;
mod import;
mod limits;
mod reference;
mod retention;
mod scope;
mod signature;
mod span;
mod walk;
mod written_type;

pub use binding::{GoBindingFact, GoBindingKind, GoInitializer, GoInitializerForm};
pub use condition::{GoBuildConditionFact, GoBuildConditionKind};
pub use declaration::{GoDeclarationFact, GoDeclarationKind};
pub use error::GoFactError;
pub use facts::GoFileFacts;
pub use import::{GoImportFact, GoImportForm};
pub use limits::GoFactLimits;
pub use reference::{GoReferenceFact, GoReferenceKind};
pub use scope::{GoScopeFact, GoScopeKind};
pub use signature::{GoSignatureRole, GoSignatureTermFact};
pub use span::GoFactSpan;

pub(crate) use facts::offer_unit_declarations;
