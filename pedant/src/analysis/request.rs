pub(crate) struct AnalysisRequest<'a> {
    pub(crate) files: &'a [String],
    pub(crate) stdin: bool,
    pub(crate) collect_source_hash: bool,
}
