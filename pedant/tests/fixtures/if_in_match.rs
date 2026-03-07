fn example(x: Option<i32>) {
    match x {
        Some(v) => {
            if v > 0 {
                println!("positive");
            }
        }
        None => {}
    }
}
