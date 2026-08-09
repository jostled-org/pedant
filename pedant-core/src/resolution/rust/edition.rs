//! Cargo package editions as resolved from direct and workspace fields.

use std::fmt;

/// A Rust edition Cargo can assign to a package.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CargoEdition {
    /// The original edition, and Cargo's default when `edition` is omitted.
    #[default]
    Rust2015,
    /// The Rust 2018 edition.
    Rust2018,
    /// The Rust 2021 edition.
    Rust2021,
    /// The Rust 2024 edition.
    Rust2024,
}

impl CargoEdition {
    pub(super) fn parse(text: &str) -> Option<Self> {
        match text {
            "2015" => Some(Self::Rust2015),
            "2018" => Some(Self::Rust2018),
            "2021" => Some(Self::Rust2021),
            "2024" => Some(Self::Rust2024),
            _ => None,
        }
    }

    pub(in crate::resolution::rust) fn permits_bare_callable_traits(self) -> bool {
        matches!(self, Self::Rust2015 | Self::Rust2018)
    }
}

impl fmt::Display for CargoEdition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Rust2015 => "2015",
            Self::Rust2018 => "2018",
            Self::Rust2021 => "2021",
            Self::Rust2024 => "2024",
        };
        formatter.write_str(text)
    }
}
