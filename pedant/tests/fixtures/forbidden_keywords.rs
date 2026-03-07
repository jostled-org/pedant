fn uses_else(x: i32) -> &'static str {
    if x > 0 {
        "positive"
    } else {
        "non-positive"
    }
}

fn uses_unsafe() {
    unsafe {
        let ptr: *const i32 = std::ptr::null();
        let _ = *ptr;
    }
}

fn clean_function(x: i32) -> i32 {
    match x > 0 {
        true => x,
        false => -x,
    }
}
