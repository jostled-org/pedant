use std::sync::Arc;

use serde::Deserialize;

type ArcStrSlice = Arc<[Arc<str>]>;

pub(super) fn deserialize_arc_str_slice<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<ArcStrSlice, D::Error> {
    let strings: Vec<String> = Vec::deserialize(deserializer)?;
    Ok(strings.into_iter().map(Arc::from).collect())
}

pub(super) fn deserialize_option_arc_str_slice<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ArcStrSlice>, D::Error> {
    let opt: Option<Vec<String>> = Option::deserialize(deserializer)?;
    Ok(opt.map(|values| values.into_iter().map(Arc::from).collect()))
}
