pub fn greet() -> &'static str {
    "hello"
}

/// Duplicate detection fixture: same skeleton as process_items/process_widgets,
/// but calls `.count()` instead of `.sum()` — parametric match (same skeleton, different exact).
pub fn handle_items(data: &[i32]) -> i32 {
    let total = data.iter().count() as i32;
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
