use std::sync::Arc;

trait Process {
    fn run(&self);
}

fn create_boxed() -> Box<dyn Process> {
    todo!()
}

fn create_arced() -> Arc<dyn Process> {
    todo!()
}

fn normal_return() -> i32 {
    42
}
