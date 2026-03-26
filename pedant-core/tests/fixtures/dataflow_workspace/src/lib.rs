use std::net::TcpStream;
use std::sync::Mutex;

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

// --- Quality: dead store ---

fn compute_something() -> i32 {
    42
}

fn compute_other() -> i32 {
    99
}

fn use_value(x: i32) {
    println!("{x}");
}

/// Dead store: first value of `x` is overwritten before being read.
pub fn dead_store() {
    let mut x = compute_something();
    x = compute_other();
    use_value(x);
}

/// No dead store: first value is read before reassignment.
pub fn no_dead_store() {
    let mut x = compute_something();
    println!("{x}");
    x = compute_other();
    use_value(x);
}

// --- Quality: discarded result ---

/// Result from `remove_file` is discarded (not bound).
pub fn discarded_result() {
    std::fs::remove_file("temp.txt");
}

/// Result is intentionally discarded with `let _ =` (caught by syntactic check).
pub fn discarded_result_bound() {
    let _ = std::fs::remove_file("temp.txt");
}

// --- Quality: partial error handling ---

/// Some paths handle the Result, others drop it silently.
pub fn partial_error_handling(flag: bool) -> String {
    let data = std::fs::read_to_string("file.txt");
    match flag {
        true => data.unwrap_or_default(),
        false => {
            data;
            String::new()
        }
    }
}

// --- Performance: repeated call ---

fn expensive_compute(n: i32) -> i32 {
    n * n
}

fn use_both(a: i32, b: i32) {
    println!("{a} {b}");
}

/// Same function called twice with identical arguments.
pub fn repeated_call_same_args() {
    let a = expensive_compute(42);
    let b = expensive_compute(42);
    use_both(a, b);
}

/// Different arguments — no repeated call.
pub fn repeated_call_different_args() {
    let a = expensive_compute(1);
    let b = expensive_compute(2);
    use_both(a, b);
}

// --- Performance: unnecessary clone ---

fn consume(s: String) {
    println!("{s}");
}

/// Clone where original is never used after — clone was unnecessary.
pub fn unnecessary_clone(s: String) {
    let cloned = s.clone();
    consume(cloned);
}

/// Clone where original is used after — clone is necessary.
pub fn clone_needed(s: String) {
    let cloned = s.clone();
    consume(cloned);
    consume(s);
}

// --- Performance: allocation in loop ---

fn fill(v: &mut Vec<u8>) {
    v.push(1);
}

fn process(v: &[u8]) {
    println!("{}", v.len());
}

/// Vec allocated inside loop body on every iteration.
pub fn allocation_in_loop() {
    for _i in 0..100 {
        let mut v = Vec::<u8>::new();
        fill(&mut v);
        process(&v);
    }
}

// --- Performance: redundant collect ---

/// Collects into Vec then immediately re-iterates.
pub fn redundant_collect(items: &[i32]) -> i32 {
    let collected: Vec<i32> = items.iter().copied().collect();
    collected.into_iter().sum()
}

// --- Concurrency: lock across await ---

async fn do_async_work() {
    std::future::pending::<()>().await;
}

/// Lock guard held across an await point — potential deadlock.
#[allow(clippy::await_holding_lock)]
pub async fn lock_across_await_direct() {
    let mutex = Mutex::new(42);
    let guard = mutex.lock().unwrap();
    do_async_work().await;
    drop(guard);
}

async fn helper_async() {
    std::future::pending::<()>().await;
}

/// Lock guard held across an async function call — cross-function await.
#[allow(clippy::await_holding_lock)]
pub async fn lock_across_await_cross_fn() {
    let mutex = Mutex::new(42);
    let guard = mutex.lock().unwrap();
    helper_async().await;
    drop(guard);
}

/// Lock guard dropped before await — safe pattern.
pub async fn lock_dropped_before_await() {
    let mutex = Mutex::new(42);
    let data = {
        let guard = mutex.lock().unwrap();
        *guard
    };
    do_async_work().await;
    use_value(data);
}

// --- Concurrency: inconsistent lock ordering ---

/// Locks m1 then m2.
pub fn lock_order_a(m1: &Mutex<()>, m2: &Mutex<()>) {
    let _a = m1.lock().unwrap();
    let _b = m2.lock().unwrap();
}

/// Locks m2 then m1 — inconsistent with lock_order_a.
pub fn lock_order_b(m1: &Mutex<()>, m2: &Mutex<()>) {
    let _b = m2.lock().unwrap();
    let _a = m1.lock().unwrap();
}

/// Locks m1 then m2 — consistent with lock_order_a.
pub fn lock_order_consistent(m1: &Mutex<()>, m2: &Mutex<()>) {
    let _a = m1.lock().unwrap();
    let _b = m2.lock().unwrap();
}
