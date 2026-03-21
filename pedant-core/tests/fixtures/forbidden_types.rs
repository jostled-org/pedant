use std::sync::Arc;

struct MyStruct {
    name: Arc<String>,
    data: Arc<Vec<i32>>,
}

fn takes_arc_string(s: Arc<String>) -> String {
    s.to_string()
}

fn takes_box_error(e: Box<dyn std::error::Error>) -> String {
    e.to_string()
}

fn clean_function() -> Arc<str> {
    Arc::from("hello")
}

fn clean_vec() -> Vec<String> {
    vec![]
}
