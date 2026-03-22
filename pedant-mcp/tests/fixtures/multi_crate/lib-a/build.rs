use reqwest::blocking::get;

fn main() {
    let _resp = get("https://example.com/config");
    println!("cargo:rerun-if-changed=build.rs");
}
