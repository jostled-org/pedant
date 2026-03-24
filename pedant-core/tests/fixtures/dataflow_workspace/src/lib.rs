use std::net::TcpStream;

/// Direct call: `run()` calls `fetch()`.
fn fetch() {
    let _ = TcpStream::connect("127.0.0.1:8080");
}

/// Entry point calling `fetch`.
pub fn run() {
    fetch();
}

/// No function calls — returns a constant.
pub fn no_calls() -> i32 {
    42
}

/// Public function using network directly.
pub fn reachable_network() {
    let _ = TcpStream::connect("127.0.0.1:8080");
}

/// Private function, never called — unreachable dead code.
fn unreachable_private() {
    let _ = TcpStream::connect("127.0.0.1:8080");
}

/// Reads env var and sends it over the network — taint path.
pub fn leak_env() {
    let key = std::env::var("SECRET").unwrap_or_default();
    let _ = TcpStream::connect(&*key);
}

/// Reads env var but only prints it — no taint flow to sink.
pub fn safe_env() {
    let path = std::env::var("PATH").unwrap_or_default();
    println!("{path}");
}
