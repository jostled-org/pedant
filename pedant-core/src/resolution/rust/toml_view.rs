//! Borrowed accessors over a parsed Cargo manifest table.
//!
//! The project model reads manifests without `serde`, which stays behind the
//! judgment surface, so every lookup goes through these helpers.

/// A nested table, when the key holds one.
pub(super) fn table<'a>(parent: &'a toml::Table, key: &str) -> Option<&'a toml::Table> {
    parent.get(key).and_then(toml::Value::as_table)
}

/// A string value, when the key holds one.
pub(super) fn string<'a>(parent: &'a toml::Table, key: &str) -> Option<&'a str> {
    parent.get(key).and_then(toml::Value::as_str)
}

/// A boolean value, or `default` when the key is absent or another type.
pub(super) fn flag(parent: &toml::Table, key: &str, default: bool) -> bool {
    parent
        .get(key)
        .and_then(toml::Value::as_bool)
        .unwrap_or(default)
}

/// Every string in an array value, skipping entries of another type.
pub(super) fn strings(parent: &toml::Table, key: &str) -> Box<[Box<str>]> {
    parent
        .get(key)
        .and_then(toml::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(toml::Value::as_str)
                .map(Box::<str>::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Every table in an array-of-tables value.
pub(super) fn tables<'a>(parent: &'a toml::Table, key: &str) -> Box<[&'a toml::Table]> {
    parent
        .get(key)
        .and_then(toml::Value::as_array)
        .map(|values| values.iter().filter_map(toml::Value::as_table).collect())
        .unwrap_or_default()
}

/// Whether a key requests workspace inheritance, as in `version.workspace = true`.
pub(super) fn inherits(parent: &toml::Table, key: &str) -> bool {
    table(parent, key).is_some_and(|entry| flag(entry, "workspace", false))
}

/// The first table present among alias spellings of one Cargo key.
pub(super) fn aliased_table<'a>(parent: &'a toml::Table, keys: &[&str]) -> Option<&'a toml::Table> {
    keys.iter().find_map(|key| table(parent, key))
}
