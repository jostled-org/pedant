use std::fmt::Write;

fn write_to_typed_string() {
    let mut buf: String = String::new();
    let _ = write!(buf, "hello {}", 42);
}

fn writeln_to_ref_mut_string(s: &mut String) {
    let buf: &mut String = s;
    let _ = writeln!(buf, "world");
}
