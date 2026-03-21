use std::fs;
use std::path::Path;

fn discards_fs_write() {
    let _ = fs::write(Path::new("/tmp/test"), b"data");
}

fn discards_function_call() {
    let _ = some_fn();
}

fn discards_method_call() {
    let _ = conn.execute("SELECT 1");
}

fn no_init_wildcard() {
    let _;
}

fn named_binding() {
    let x = 5;
}

fn some_fn() -> Result<(), ()> {
    Ok(())
}
