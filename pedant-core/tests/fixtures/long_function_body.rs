// A function whose body spans many lines including blank lines,
// comments, and brace-bearing string literals — all counted exactly.
fn long_body() {
    let opening = "{"; // a brace in a string must not confuse counting
    let closing = "}"; // and neither must this one
    let _ = opening;
    let _ = closing;

    // a comment line counts toward the body extent

    let mut total = 0;
    total += 1;
    total += 2;
    total += 3;
    let _ = total;
}

fn short_body() {
    let x = 1;
    let _ = x;
}
