//! The Rust sources every capability case analyzes.
//!
//! A submodule of `tests/capability.rs`, reached through a `#[path]` attribute
//! and not a test root of its own: this directory carries no `main.rs`, so cargo
//! declares no test executable for it. The literals live here so the root stays
//! a readable inventory of claims; every value is byte-for-byte what its case
//! always analyzed.

pub(crate) const TEST_MULTIPLE_CAPABILITIES_DETECTED: &str = r#"
use std::net::TcpStream;
use std::fs;

fn do_things() {
    let _stream = TcpStream::connect("127.0.0.1:80");
    let _content = fs::read_to_string("file.txt");
}
"#;

pub(crate) const TEST_FS_WRITE_FUNCTION_DETECTED: &str = r#"
fn write_file() {
    let _ = std::fs::write("out.txt", "data");
}
"#;

pub(crate) const TEST_FFI_CAPABILITY_EXTERN_BLOCK: &str = r#"
extern "C" {
    fn my_c_function(x: i32) -> i32;
}
"#;

pub(crate) const TEST_UNSAFE_BLOCK_DETECTED: &str = r#"
fn foo() {
    let _val = unsafe { 42 };
}
"#;

pub(crate) const TEST_UNSAFE_FN_DETECTED: &str = r#"
unsafe fn dangerous() -> i32 {
    42
}
"#;

pub(crate) const TEST_UNSAFE_IMPL_DETECTED: &str = r#"
struct MyType;
unsafe impl Send for MyType {}
"#;

pub(crate) const TEST_HARDCODED_URL_DETECTED: &str = r#"
fn foo() {
    let _url = "https://api.example.com/v1/data";
}
"#;

pub(crate) const TEST_HARDCODED_IP_DETECTED: &str = r#"
fn foo() {
    let _ip = "192.168.1.1:8080";
}
"#;

pub(crate) const TEST_IPV6_DETECTED: &str = r#"
fn foo() {
    let _ip = "[::1]:8080";
}
"#;

pub(crate) const TEST_OID_STRING_IS_NOT_NETWORK: &str = r#"
pub const OID: &str = "2.5.4.10";
"#;

pub(crate) const TEST_RUST_PATH_STRING_IS_NOT_NETWORK: &str = r#"
pub const PATH: &str = "A::B::C::D::E::F";
"#;

pub(crate) const TEST_VERSION_STRING_IS_NOT_NETWORK: &str = r#"
pub const VERSION: &str = "1.2.3.40";
"#;

pub(crate) const TEST_SHORT_STRING_NOT_FLAGGED: &str = r#"
fn foo() {
    let _s = "hello";
}
"#;

pub(crate) const TEST_PEM_KEY_MATERIAL_DETECTED: &str = r#"
fn foo() {
    let _key = "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----";
}
"#;

pub(crate) const TEST_PROC_MACRO_DETECTED: &str = r#"
#[proc_macro]
fn my_macro(input: TokenStream) -> TokenStream {
    input
}
"#;

pub(crate) const TEST_PROC_MACRO_DERIVE_DETECTED: &str = r#"
#[proc_macro_derive(Foo)]
fn my_derive(input: TokenStream) -> TokenStream {
    input
}
"#;

pub(crate) const TEST_BUILD_SCRIPT_FINDINGS_TAGGED: &str = r#"
use std::process::Command;

fn main() {
    Command::new("cc").status().unwrap();
}
"#;

pub(crate) const TEST_HEX_SHORT_NOT_FLAGGED: &str = r#"
fn foo() {
    let _hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
}
"#;

pub(crate) const TEST_HEX_ODD_LENGTH_NOT_FLAGGED: &str = r#"
fn foo() {
    let _odd = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2a";
}
"#;

pub(crate) const TEST_HEX_MIXED_CASE_DETECTED: &str = r#"
fn foo() {
    let _key = "aAbBcCdDeEfF0011aAbBcCdDeEfF0011aAbBcCdDeEfF0011aAbBcCdDeEfF0011";
}
"#;

pub(crate) const TEST_BITCOIN_WIF_K_PREFIX_DETECTED: &str = r#"
fn foo() {
    let _key = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
}
"#;

pub(crate) const TEST_SHORT_BASE58_NOT_FLAGGED: &str = r#"
fn foo() {
    let _addr = "1A1zP1eP5QGefi2DM";
}
"#;

pub(crate) const TEST_BASE58_WITH_INVALID_CHARS_NOT_FLAGGED: &str = r#"
fn foo() {
    let _not_key = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVq0OIl";
}
"#;

pub(crate) const TEST_ETHEREUM_PRIVATE_KEY_DETECTED: &str = r#"
fn foo() {
    let _key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
}
"#;

pub(crate) const TEST_NEAR_ED25519_KEY_DETECTED: &str = r#"
fn foo() {
    let _key = "ed25519:3D4YudUahN1nawWogh6LMPvoRPW8QHr9AJsByJsXk7gn";
}
"#;

pub(crate) const TEST_GITHUB_PAT_DETECTED: &str = r#"
fn foo() {
    let _token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
}
"#;

pub(crate) const TEST_STRIPE_SECRET_KEY_DETECTED: &str = r#"
fn foo() {
    let _key = "sk_live_abcdefghijklmnopqrstuvwx";
}
"#;

pub(crate) const TEST_SHORT_0X_NOT_FLAGGED: &str = r#"
fn foo() {
    let _val = "0xdeadbeef12";
}
"#;

pub(crate) const TEST_EXISTING_PEM_STILL_WORKS_PEM_SOURCE: &str = r#"
fn foo() {
    let _key = "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----";
}
"#;

pub(crate) const STRING_LITERAL_FINDING_HAS_STRING_LITERAL_ORIGIN: &str = r#"
fn foo() {
    let _url = "https://api.example.com/v1/data";
}
"#;

pub(crate) const KEY_MATERIAL_FINDING_HAS_STRING_LITERAL_ORIGIN: &str = r#"
fn foo() {
    let _key = "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----";
}
"#;

pub(crate) const ATTRIBUTE_FINDING_HAS_ATTRIBUTE_ORIGIN: &str = r#"
#[proc_macro]
fn my_macro(input: TokenStream) -> TokenStream {
    input
}
"#;

pub(crate) const UNSAFE_BLOCK_FINDING_HAS_CODE_SITE_ORIGIN: &str = r#"
fn foo() {
    let _val = unsafe { 42 };
}
"#;

pub(crate) const EXTERN_BLOCK_FINDING_HAS_CODE_SITE_ORIGIN: &str = r#"
extern "C" {
    fn my_c_function(x: i32) -> i32;
}
"#;

pub(crate) const LINK_ATTRIBUTE_FINDING_HAS_ATTRIBUTE_ORIGIN: &str = r#"
#[link(name = "mylib")]
extern "C" {
    fn my_c_function(x: i32) -> i32;
}
"#;
