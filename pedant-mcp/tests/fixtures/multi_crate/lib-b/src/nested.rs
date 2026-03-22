pub fn deeply_nested(x: i32) {
    if x > 0 {
        if x > 1 {
            if x > 2 {
                if x > 3 {
                    println!("deep");
                }
            }
        }
    }
}
