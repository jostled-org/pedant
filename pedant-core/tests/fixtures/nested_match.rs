fn example(a: Option<i32>, b: Option<i32>) {
    match a {
        Some(x) => {
            match b {
                Some(y) => println!("{} {}", x, y),
                None => {}
            }
        }
        None => {}
    }
}
