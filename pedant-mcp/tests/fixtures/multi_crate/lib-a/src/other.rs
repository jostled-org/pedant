use std::fs;

pub fn read_config() -> std::io::Result<String> {
    fs::read_to_string("config.toml")
}

/// Duplicate detection fixture: identical structure to `process_items` in lib.rs.
/// Same control flow, same method calls, same bindings — only names differ.
pub fn process_widgets(data: &[i32]) -> i32 {
    let total = data.iter().sum::<i32>();
    if total > 100 {
        let filtered: Vec<_> = data.iter().filter(|x| **x > 0).collect();
        match filtered.len() {
            0 => -1,
            n => n as i32,
        }
    } else {
        total
    }
}
