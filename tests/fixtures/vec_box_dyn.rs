trait Plugin {
    fn name(&self) -> &str;
}

struct Registry {
    plugins: Vec<Box<dyn Plugin>>,
}

fn make_plugins() -> Vec<Box<dyn Plugin>> {
    Vec::new()
}

fn normal_vec() -> Vec<i32> {
    Vec::new()
}
