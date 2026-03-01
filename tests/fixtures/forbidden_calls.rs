fn uses_unwrap() -> i32 {
    let opt: Option<i32> = Some(42);
    opt.unwrap()
}

fn uses_expect() -> i32 {
    let opt: Option<i32> = Some(42);
    opt.expect("should have value")
}

fn uses_clone() -> String {
    let s = String::from("hello");
    s.clone()
}

fn clean_function() -> i32 {
    let opt: Option<i32> = Some(42);
    opt.unwrap_or(0)
}
