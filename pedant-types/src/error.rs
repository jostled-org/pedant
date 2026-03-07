/// Errors from type serialization/deserialization.
#[derive(Debug, thiserror::Error)]
pub enum TypeError {
    /// JSON serialization or deserialization failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}
