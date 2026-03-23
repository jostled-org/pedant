use std::fmt;

/// Error returned when parsing an unknown capability name.
#[derive(Debug, Clone)]
pub struct ParseCapabilityError {
    name: Box<str>,
}

impl ParseCapabilityError {
    /// Create a new error for the given unrecognized capability name.
    pub fn new(name: &str) -> Self {
        Self {
            name: Box::from(name),
        }
    }
}

impl fmt::Display for ParseCapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown capability: {}", self.name)
    }
}

impl std::error::Error for ParseCapabilityError {}
