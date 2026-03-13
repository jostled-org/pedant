/// Errors from type serialization/deserialization.
/// Single variant today; enum allows adding variants without breaking callers.
#[derive(Debug, thiserror::Error)]
pub enum TypeError {
    /// JSON serialization or deserialization failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}
