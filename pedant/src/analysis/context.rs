use pedant_core::SemanticContext;
use pedant_core::check_config::CheckConfig;

pub(crate) struct AnalysisContext<'a> {
    pub(crate) base_config: &'a CheckConfig,
    pub(crate) file_config: Option<&'a pedant_core::check_config::ConfigFile>,
    pub(crate) semantic: Option<&'a SemanticContext>,
}
