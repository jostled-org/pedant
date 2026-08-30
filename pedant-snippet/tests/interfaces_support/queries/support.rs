//! What every navigation case asks of a built state, stated once.

use std::fmt::Debug;

use serde::Serialize;
use serde::de::DeserializeOwned;

use pedant_snippet::{
    CodeIntelligenceError, CodeIntelligenceState, MatchMode, NavigationResponse, PageCursor,
    PageRequest, StructureDescriptor, SymbolQuery,
};

use super::answer::Answer;
use crate::index::fixture::Repository;
use crate::index::harness::indexed;
use crate::index::sources::{BROKEN_SOURCE, MIXED_REPOSITORY};

/// The mixed six-language repository, indexed under the host defaults.
///
/// The repository is returned with the state because it owns the temporary
/// tree: dropping it removes the directory, and a case that let it drop while
/// still querying would be proving something about a repository that no longer
/// exists rather than about the index.
pub fn mixed() -> (Repository, CodeIntelligenceState) {
    let repository = Repository::of(MIXED_REPOSITORY);
    let state = indexed(&repository);
    (repository, state)
}

/// The mixed repository with one source no inventory accepts.
///
/// The refused source is admitted by no index, so this state and [`mixed`]'s
/// state claim one index identity and two state identities. That is the only
/// shape in which a health transition can be told from a corpus change, and it
/// is what the shared contract's state-revision row is taken over.
pub fn degraded_mixed() -> (Repository, CodeIntelligenceState) {
    let repository = Repository::of(MIXED_REPOSITORY);
    repository.write("broken.py", BROKEN_SOURCE);
    let state = indexed(&repository);
    (repository, state)
}

/// One symbol search with no filters.
pub fn search(text: &str, mode: MatchMode) -> SymbolQuery {
    SymbolQuery {
        text: Box::from(text),
        mode,
        language: None,
        kind: None,
        owner_name: None,
        path_prefix: None,
    }
}

/// The first page of a paged query, at the host default size.
///
/// A request that states neither a size nor a cursor, which is what [`page`]
/// already builds. Named because that is the question these call sites ask.
pub fn first_page() -> PageRequest {
    page(None, None)
}

/// One page of `size` items, continuing `cursor`.
pub fn page(size: Option<u32>, cursor: Option<PageCursor>) -> PageRequest {
    PageRequest { size, cursor }
}

/// The envelope both transports send survives one trip through its wire form.
///
/// Stated once over every answer type rather than per operation. The envelope
/// is one type, and a round trip written out at four call sites is four places
/// for the fifth answer to be the one nobody serialized.
///
/// The restored envelope is compared to the original value, not only to its own
/// rendering. A field dropped on the way out and defaulted on the way back in
/// renders identically twice. A cursor a transport swallowed would satisfy a
/// text comparison and still strand every caller on the first page.
pub fn the_envelope_round_trips<Payload: Debug + PartialEq + Serialize + DeserializeOwned>(
    response: &NavigationResponse<Payload>,
) {
    let rendered = serde_json::to_string(response).expect("the response serializes");
    let restored: NavigationResponse<Payload> =
        serde_json::from_str(&rendered).expect("and round trips");
    assert_eq!(
        &restored, response,
        "the envelope both transports send states the same answer after a round trip"
    );
    assert_eq!(
        serde_json::to_string(&restored).expect("the restored response serializes"),
        rendered,
        "and renders the same bytes the second time"
    );
}

/// Every matched structure, as its qualified name.
///
/// Private to this file: [`symbols_page`] is the one way a root reads a search
/// as identities, so a caller that wants every match takes it through the paged
/// helper and inherits that helper's refusal of a cut-short result.
///
/// Boxed rather than a `Vec`: one `collect` builds it and the consumer then
/// compares it. Collected straight into the boxed slice, because the consumer
/// that hands it to [`Answer`] used to reallocate and copy the whole list to
/// shed a capacity nothing had grown.
fn qualified(matched: &[StructureDescriptor]) -> Box<[String]> {
    matched
        .iter()
        .map(|structure| structure.qualified_name().to_owned())
        .collect()
}

/// What the symbol search is called in a failure message.
///
/// Beside the adapter it names, because a label is only useful if every root
/// that pages this operation reports under the same one: three spellings of it
/// are three different operations to a reader of a failing run.
pub const SEARCH_LABEL: &str = "search_symbols";

/// What the project listing is called in a failure message.
pub const LISTING_LABEL: &str = "list_projects";

/// One page of `search_symbols`, reduced to what the paged table reads.
///
/// Published once. Three roots page this operation against the shared
/// contract, and three private adapters were three chances for one of them to
/// state a weaker identity than the others.
pub fn symbols_page(
    state: &CodeIntelligenceState,
    query: &SymbolQuery,
    request: &PageRequest,
) -> Result<Answer, CodeIntelligenceError> {
    state.search_symbols(query, request).map(|response| Answer {
        identities: qualified(response.result()),
        next: response.next_page(),
    })
}

/// One page of `list_projects`, reduced to what the paged table reads.
///
/// A project is identified by its language and its unit together, which is the
/// key the listing is ordered by. The unit alone would let a traversal row pass
/// while two projects of different languages traded places.
pub fn projects_page(
    state: &CodeIntelligenceState,
    request: &PageRequest,
) -> Result<Answer, CodeIntelligenceError> {
    state.list_projects(request).map(|response| Answer {
        identities: response
            .result()
            .iter()
            .map(|project| format!("{:?}|{}", project.language(), project.unit()))
            .collect(),
        next: response.next_page(),
    })
}

/// One attempted operation as a failure message names it.
pub fn rendered<T>(outcome: &Result<T, CodeIntelligenceError>) -> String {
    match outcome {
        Ok(_) => "an answer".to_owned(),
        Err(error) => error.to_string(),
    }
}

/// The source text the index retained for one admitted path.
///
/// Named for the source rather than for the retention, because `pedant-syntax`
/// publishes a `retained` of its own that answers with an inventory, and the
/// outline root reads both within a few lines of each other.
///
/// One lookup site. Five call sites across the outline and source roots wrote
/// out the same `index().file(path)` walk with a panic message of their own, and
/// a reader of one of those messages could not tell which of the five had asked
/// for a path the index does not hold.
pub fn retained_source<'index>(state: &'index CodeIntelligenceState, path: &str) -> &'index str {
    state
        .index()
        .file(path)
        .unwrap_or_else(|error| panic!("{path} is an admitted source: {error}"))
        .text()
}

/// The one-based line and byte column the byte at `offset` sits at.
///
/// One implementation, because a line and a column are one walk of the same
/// prefix and three roots were computing them apart. A `get` that fails means
/// `offset` is past the text or inside a character, which is a broken span
/// rather than a position: it panics here instead of counting zero newlines
/// and reporting line 1, which compares equal for every structure that really
/// does open on the first line.
pub fn position_of(text: &str, offset: usize) -> (u32, u32) {
    let prefix = text
        .get(..offset)
        .unwrap_or_else(|| panic!("offset {offset} is a boundary of the retained source"));
    let line = prefix.matches('\n').count() + 1;
    let column = offset - prefix.rfind('\n').map_or(0, |cut| cut + 1) + 1;
    (
        u32::try_from(line).expect("a small line"),
        u32::try_from(column).expect("a small column"),
    )
}

/// The one-based line the byte at `offset` sits on.
pub fn line_at(text: &str, offset: usize) -> u32 {
    position_of(text, offset).0
}

/// The one-based byte column the byte at `offset` sits at.
#[cfg(feature = "test-support")]
pub fn column_of(text: &str, offset: usize) -> u32 {
    position_of(text, offset).1
}
