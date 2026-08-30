//! The one `Serialize` every closed vocabulary here is written through.
//!
//! Each of these enums already publishes a `token()`, because a text row prints
//! the spelling the JSON carries and a renderer with no accessor to read had to
//! serialize the value and strip the quotes. That leaves two statements of the
//! same strings: the accessor, and whatever `Serialize` writes. A derive plus
//! `rename_all` is one such second statement, a hand-written `serialize_str` is
//! another, and nothing holds either of them to the accessor — a variant
//! renamed without its `token` arm sends one spelling and reports the other.
//!
//! So the accessor is the wire, once. `Deserialize` stays derived wherever a
//! vocabulary is read back: `rename_all` reads the same names this writes, and
//! a decoder that drifted from the encoder fails a round trip a test already
//! takes.

/// Write one closed vocabulary as the token its own accessor names.
///
/// The accessor takes `self` by value, because every vocabulary this is applied
/// to is `Copy`.
macro_rules! serialize_token {
    ($vocabulary:ident) => {
        impl serde::Serialize for $vocabulary {
            fn serialize<Target: serde::Serializer>(
                &self,
                serializer: Target,
            ) -> Result<Target::Ok, Target::Error> {
                serializer.serialize_str(self.token())
            }
        }
    };
}

pub(super) use serialize_token;
