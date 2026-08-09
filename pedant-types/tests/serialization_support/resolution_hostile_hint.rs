//! A deserializer that advertises an untrusted sequence capacity.

use std::cell::Cell;
use std::rc::Rc;

use pedant_types::resolution::{ResolutionReport, ResolutionReportError, ResolutionReportLimits};
use serde::de::value::Error as ValueError;
use serde::de::{
    DeserializeSeed, Deserializer, Error as DeserializeError, IntoDeserializer, MapAccess,
    SeqAccess, Visitor,
};

/// Prove report decoding never reads or allocates from an untrusted size hint.
pub fn assert_hostile_size_hint_is_not_observed() {
    let hint_observed = Rc::new(Cell::new(false));
    let deserializer = HostileInput::report(Rc::clone(&hint_observed));
    let reported = ResolutionReport::deserialize_with_limits(
        deserializer,
        ResolutionReportLimits {
            max_units: 0,
            ..ResolutionReportLimits::default()
        },
    )
    .expect_err("the first unit exceeds a zero-unit limit")
    .to_string();

    let expected = ResolutionReportError::UnitCapacityExceeded { limit: 0 };
    assert!(reported.starts_with(&expected.to_string()));
    assert!(
        !hint_observed.get(),
        "the bounded decoder must not inspect an untrusted size hint",
    );
}

enum InputMode {
    Report { field: u8 },
    Sequence { yielded: bool },
}

struct HostileInput {
    mode: InputMode,
    hint_observed: Rc<Cell<bool>>,
}

impl HostileInput {
    fn report(hint_observed: Rc<Cell<bool>>) -> Self {
        Self {
            mode: InputMode::Report { field: 0 },
            hint_observed,
        }
    }

    fn sequence(hint_observed: Rc<Cell<bool>>) -> Self {
        Self {
            mode: InputMode::Sequence { yielded: false },
            hint_observed,
        }
    }
}

impl<'de> Deserializer<'de> for HostileInput {
    type Error = ValueError;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.mode {
            InputMode::Report { .. } => visitor.visit_map(self),
            InputMode::Sequence { .. } => visitor.visit_seq(self),
        }
    }

    fn deserialize_struct<V>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_any(visitor)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_any(visitor)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes
        byte_buf option unit unit_struct newtype_struct tuple tuple_struct map
        enum identifier ignored_any
    }
}

impl<'de> MapAccess<'de> for HostileInput {
    type Error = ValueError;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: DeserializeSeed<'de>,
    {
        let field = match &mut self.mode {
            InputMode::Report { field } => field,
            InputMode::Sequence { .. } => {
                return Err(ValueError::custom("sequence input was read as a map"));
            }
        };
        let name = match *field {
            0 => "tier",
            1 => "units",
            _ => return Ok(None),
        };
        *field += 1;
        seed.deserialize(name.into_deserializer()).map(Some)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        let field = match &self.mode {
            InputMode::Report { field } => *field,
            InputMode::Sequence { .. } => {
                return Err(ValueError::custom("sequence input was read as a map"));
            }
        };
        match field {
            1 => seed.deserialize("syntactic".into_deserializer()),
            2 => seed.deserialize(Self::sequence(Rc::clone(&self.hint_observed))),
            _ => Err(ValueError::custom("a value was requested without a field")),
        }
    }
}

impl<'de> SeqAccess<'de> for HostileInput {
    type Error = ValueError;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        let yielded = match &mut self.mode {
            InputMode::Sequence { yielded } => yielded,
            InputMode::Report { .. } => {
                return Err(ValueError::custom("map input was read as a sequence"));
            }
        };
        match *yielded {
            true => Ok(None),
            false => {
                *yielded = true;
                seed.deserialize(().into_deserializer()).map(Some)
            }
        }
    }

    fn size_hint(&self) -> Option<usize> {
        self.hint_observed.set(true);
        Some(usize::MAX)
    }
}
