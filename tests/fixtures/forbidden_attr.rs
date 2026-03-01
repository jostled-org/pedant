#[allow(dead_code)]
fn unused_function() {}

#[allow(unused_variables)]
fn another_function(x: i32) {}

#[allow(clippy::unwrap_used)]
fn clippy_suppressed() {}

#[derive(Debug)]
struct MyStruct;

fn clean_function() -> i32 {
    42
}
