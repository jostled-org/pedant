use std::collections::{HashMap, HashSet};

struct Index {
    entries: HashMap<u64, Vec<String>>,
    seen: HashSet<String>,
}

fn make_map() -> HashMap<String, i32> {
    HashMap::new()
}

fn make_set() -> HashSet<i32> {
    HashSet::new()
}
