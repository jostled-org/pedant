use reqwest::get;

fn main() {
    let _response = get("https://example.com/build-dep.tar.gz");
}
