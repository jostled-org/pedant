fn uses_panic() {
    panic!("something went wrong");
}

fn uses_todo() {
    todo!("implement this later");
}

fn uses_unimplemented() {
    unimplemented!("not yet");
}

fn uses_dbg() {
    let x = 42;
    dbg!(x);
}

fn uses_println() {
    println!("Hello, world!");
}

fn clean_function() {
    let _ = format!("allowed");
}
