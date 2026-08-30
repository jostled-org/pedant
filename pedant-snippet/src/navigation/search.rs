//! Which named structures a search states, and in which order.

use pedant_types::{Language, StructureKind, StructureSpan};

use crate::index::{
    CodeIntelligenceError, CodeIntelligenceIndex, CodeIntelligenceState, CodeStructure, PagedQuery,
    QueryField, RevisionClaim, RevisionClaimInput, normalize,
};

use super::describe::{Describer, named_owners};
use super::page::Window;
use super::page_request::PageRequest;
use super::paged_query::PagedRequest;
use super::record::StructureDescriptor;
use super::request::SymbolQuery;
use super::response::NavigationResponse;

/// Answer [`CodeIntelligenceState::search_symbols`].
pub(crate) fn symbols_selected(
    state: &CodeIntelligenceState,
    query: &SymbolQuery,
    request: &PageRequest,
) -> Result<NavigationResponse<Box<[StructureDescriptor]>>, CodeIntelligenceError> {
    let selection = SymbolSelection::of(query)?;
    let window = Window::opened(state, &selection, request)?;

    let index = state.index();
    let mut matched: Vec<&CodeStructure> = index
        .structures()
        .iter()
        .filter(|structure| selection.matches(index, structure))
        .collect();
    matched.sort_by(|left, right| order(left).cmp(&order(right)));

    let selected = window.page(&matched)?;
    let mut describer = Describer::new(index);
    let described: Box<[StructureDescriptor]> = selected
        .iter()
        .map(|structure| describer.describe(structure))
        .collect();
    Ok(NavigationResponse::paged(
        state,
        described,
        window.next(state, &selection, matched.len()),
    ))
}

/// The fixed order a search states its matches in.
///
/// The span orders by start byte and then end byte, and the kind orders by the
/// closed vocabulary's own declaration order — neither by a rendering, so no
/// formatting decision can move a result.
fn order(structure: &CodeStructure) -> (&str, StructureSpan, StructureKind, &str) {
    (
        structure.path(),
        structure.span(),
        structure.kind(),
        structure.name().unwrap_or_default(),
    )
}

/// One symbol search whose path prefix has been normalized.
///
/// Validation happens before anything is selected, so a request that is not a
/// request refuses without reading a record — and the normalized prefix is what
/// reaches the cursor binding, so two spellings of one prefix cannot mint two
/// cursors over one result.
struct SymbolSelection<'query> {
    query: &'query SymbolQuery,
    path_prefix: Option<&'query str>,
}

impl<'query> SymbolSelection<'query> {
    /// Validate one search request.
    fn of(query: &'query SymbolQuery) -> Result<Self, CodeIntelligenceError> {
        let path_prefix = query.path_prefix.as_deref().map(normalize).transpose()?;
        Ok(Self { query, path_prefix })
    }

    /// Whether one retained structure answers this search.
    fn matches(&self, index: &CodeIntelligenceIndex, structure: &CodeStructure) -> bool {
        let Some(name) = structure.name() else {
            return false;
        };
        self.query.mode.matches(name, &self.query.text)
            && self
                .query
                .language
                .is_none_or(|language| language == structure.language())
            && self.query.kind.is_none_or(|kind| kind == structure.kind())
            && self
                .path_prefix
                .is_none_or(|prefix| structure.path().starts_with(prefix))
            && self.query.owner_name.as_ref().is_none_or(|owner| {
                named_owners(index, structure)
                    .next()
                    .is_some_and(|named| named == &**owner)
            })
    }
}

impl PagedRequest for SymbolSelection<'_> {
    fn kind(&self) -> PagedQuery {
        PagedQuery::Symbols
    }

    fn claim(&self, claim: &mut RevisionClaim) {
        claim.write(RevisionClaimInput::QueryParameter {
            field: QueryField::MatchMode,
            value: Some(self.query.mode.token()),
        });
        claim.write(RevisionClaimInput::QueryParameter {
            field: QueryField::QueryText,
            value: Some(&self.query.text),
        });
        claim.write(RevisionClaimInput::QueryParameter {
            field: QueryField::Language,
            value: self.query.language.map(Language::token),
        });
        claim.write(RevisionClaimInput::QueryParameter {
            field: QueryField::Kind,
            value: self.query.kind.map(StructureKind::token),
        });
        claim.write(RevisionClaimInput::QueryParameter {
            field: QueryField::OwnerName,
            value: self.query.owner_name.as_deref(),
        });
        claim.write(RevisionClaimInput::QueryParameter {
            field: QueryField::PathPrefix,
            value: self.path_prefix,
        });
    }
}
