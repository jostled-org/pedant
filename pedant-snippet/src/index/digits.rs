//! Reading `2 * N` lowercase hex digits back into `N` bytes.
//!
//! Separate from the value the digits spell, because this is the half a
//! transport exercises: a revision and a cursor arrive as text a caller typed or
//! a client sent, and every way that text can be wrong is refused here.

use std::fmt;

use super::hex::Hex;

/// Read the digits, however the deserializer holds them.
///
/// A visitor rather than `<&str>::deserialize`, because a borrowed string is not
/// something every deserializer can supply. A revision arrives from a command
/// line as an owned `String`, and from an MCP call inside an owned
/// `serde_json::Value`; both refuse to lend, and asking for a borrow would
/// refuse every value they hold rather than the malformed ones.
pub(super) struct Digits<const N: usize>;

impl<const N: usize> serde::de::Visitor<'_> for Digits<N> {
    type Value = Hex<N>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} lowercase hex digits", Hex::<N>::DIGITS)
    }

    /// The refusal is rendered from [`expecting`](Self::expecting), not spelled
    /// again beside it. Two statements of one sentence five lines apart were two
    /// places for the digit count to change, and serde already writes the
    /// expectation of whatever visitor refused.
    fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Self::Value, E> {
        decode(text)
            .map(Hex::of)
            .ok_or_else(|| E::invalid_value(serde::de::Unexpected::Str(text), &self))
    }
}

/// The `N` bytes one `2 * N`-digit lowercase hex string states.
fn decode<const N: usize>(text: &str) -> Option<[u8; N]> {
    let digits = text.as_bytes();
    if digits.len() != Hex::<N>::DIGITS {
        return None;
    }
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let high = nibble(*digits.get(index * 2)?)?;
        let low = nibble(*digits.get(index * 2 + 1)?)?;
        *byte = (high << 4) | low;
    }
    Some(bytes)
}

/// The value one lowercase hex digit states.
fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}
