struct MyType;

unsafe fn dangerous() -> i32 {
    42
}

unsafe impl Send for MyType {}

fn uses_unsafe_block() {
    let _val = unsafe { dangerous() };
}
