use std::net::TcpStream;

pub fn connect() -> std::io::Result<TcpStream> {
    TcpStream::connect("127.0.0.1:8080")
}

/// Duplicate detection fixture: identical structure to `process_widgets` in other.rs.
pub fn process_items(data: &[i32]) -> i32 {
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

/// Trivial getter: low fact_count, should be filtered out.
pub fn get_name() -> &'static str {
    "items"
}
