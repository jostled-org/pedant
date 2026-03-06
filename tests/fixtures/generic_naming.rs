// Flagged: 3/6 = 50% > 30%, 3 >= 2
fn bad(data: i32, val: i32, tmp: i32, count: i32, items: i32, buf: i32) -> i32 {
    data + val + tmp + count + items + buf
}

// Clean: 1 generic, below min_generic_count floor
fn mostly_clean(config: i32) -> i32 {
    let tmp = config + 1;
    tmp
}

// Clean: i, j allowed in loops
fn loop_vars() {
    for i in 0..10 {
        for j in 0..10 {
            let _ = i + j;
        }
    }
}

// Clean: arithmetic present, x/y/z allowed
fn math(x: f64, y: f64) -> f64 {
    let z = x * y;
    z
}

// Flagged: no arithmetic, x/y are generic
fn non_math(x: i32, y: i32) -> String {
    format!("{x}{y}")
}

// Clean: _-prefixed names skipped
fn underscored(_tmp: i32, _data: i32) -> i32 {
    0
}

// Clean: descriptive names
fn descriptive(user_id: u64, retry_count: usize) -> String {
    format!("{user_id}:{retry_count}")
}
