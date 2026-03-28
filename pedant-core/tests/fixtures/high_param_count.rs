fn many_params(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) -> i32 {
    a + b + c + d + e + f
}

fn ok_params(a: i32, b: i32) -> i32 {
    a + b
}

struct Foo;

impl Foo {
    fn method_with_self(&self, a: i32, b: i32, c: i32, d: i32, e: i32) -> i32 {
        a + b + c + d + e
    }
}
