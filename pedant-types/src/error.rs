use thiserror::Error;

/// Returned when a string does not match any known capability variant.
#[derive(Debug, Clone, Error)]
#[error("unknown capability: {name}")]
pub struct ParseCapabilityError {
    name: Box<str>,
}

impl ParseCapabilityError {
    /// Wrap the unrecognized name for display in the error message.
    pub fn new(name: &str) -> Self {
        Self {
            name: Box::from(name),
        }
    }
}
