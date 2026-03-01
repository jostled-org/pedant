struct Foo {
    bar: Bar,
}

struct Bar;

impl Foo {
    fn get_bar(&self) -> &Bar {
        &self.bar
    }
}

struct Baz {
    qux: Qux,
}

struct Qux;

impl Baz {
    fn get_qux(&self) -> &Qux {
        &self.qux
    }
}
