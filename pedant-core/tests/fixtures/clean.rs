fn example(x: Option<i32>, y: Option<i32>) {
    match (x, y) {
        (Some(a), Some(b)) if a > 0 => println!("{} {}", a, b),
        (Some(a), None) => println!("{}", a),
        _ => {}
    }
}
