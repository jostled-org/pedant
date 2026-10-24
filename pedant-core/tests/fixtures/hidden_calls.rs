pub fn statement(x: Option<u8>) -> u8 {
    x.unwrap_or(0)
}

pub fn in_format(x: Option<&str>) -> String {
    format!("{}", x.unwrap_or("none"))
}

pub fn in_vec(x: Option<u8>) -> Vec<u8> {
    vec![x.unwrap_or(0)]
}

pub fn in_assert_macro(x: Option<u8>) {
    debug_assert!(x.unwrap() > 0);
}

pub fn path_default(x: Vec<Option<u8>>) -> Vec<u8> {
    x.into_iter().map(Option::unwrap_or_default).collect()
}

pub fn path_ok(x: Vec<Result<u8, ()>>) -> Vec<u8> {
    x.into_iter().filter_map(Result::ok).collect()
}
