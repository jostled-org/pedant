//! One file's complete structure forest, in source order.

use crate::index::{CodeIntelligenceError, CodeIntelligenceState};

use super::describe::Describer;
use super::record::{FileOutline, StructureDescriptor};
use super::response::NavigationResponse;

/// Answer [`CodeIntelligenceState::outline_file`].
pub(crate) fn outlined(
    state: &CodeIntelligenceState,
    path: &str,
) -> Result<NavigationResponse<FileOutline>, CodeIntelligenceError> {
    let index = state.index();
    let record = index.file(path)?;
    let mut describer = Describer::new(index);
    let structures: Box<[StructureDescriptor]> = index
        .file_structures(record)
        .iter()
        .map(|structure| describer.describe(structure))
        .collect();
    Ok(NavigationResponse::whole(
        state,
        FileOutline::stated(Box::from(record.path()), record.language(), structures),
    ))
}
