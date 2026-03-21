use std::process::Command;

fn main() {
    Command::new("cc").arg("src/ffi.c").status().unwrap();
}
