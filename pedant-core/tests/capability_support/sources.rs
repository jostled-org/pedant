//! The Rust sources every capability case analyzes.
//!
//! A submodule of `tests/capability.rs`, reached through a `#[path]` attribute
//! and not a test root of its own: this directory carries no `main.rs`, so cargo
//! declares no test executable for it. The literals live here so the root stays
//! a readable inventory of claims; every value is byte-for-byte what its case
//! always analyzed.
//!
//! Each constant is named after the source it is, not after one test that reads
//! it. Two cases that ask different questions of the same source read the same
//! constant, so the source is written once and parsed once per case.

pub(crate) const NET_AND_FS_IMPORTS_SOURCE: &str = r#"
use std::net::TcpStream;
use std::fs;

fn do_things() {
    let _stream = TcpStream::connect("127.0.0.1:80");
    let _content = fs::read_to_string("file.txt");
}
"#;

pub(crate) const FS_WRITE_CALL_SOURCE: &str = r#"
fn write_file() {
    let _ = std::fs::write("out.txt", "data");
}
"#;

pub(crate) const EXTERN_BLOCK_SOURCE: &str = r#"
extern "C" {
    fn my_c_function(x: i32) -> i32;
}
"#;

pub(crate) const LINK_ATTRIBUTE_EXTERN_BLOCK_SOURCE: &str = r#"
#[link(name = "mylib")]
extern "C" {
    fn my_c_function(x: i32) -> i32;
}
"#;

pub(crate) const UNSAFE_BLOCK_SOURCE: &str = r#"
fn foo() {
    let _val = unsafe { 42 };
}
"#;

pub(crate) const UNSAFE_FN_SOURCE: &str = r#"
unsafe fn dangerous() -> i32 {
    42
}
"#;

pub(crate) const UNSAFE_IMPL_SOURCE: &str = r#"
struct MyType;
unsafe impl Send for MyType {}
"#;

pub(crate) const HTTPS_URL_SOURCE: &str = r#"
fn foo() {
    let _url = "https://api.example.com/v1/data";
}
"#;

pub(crate) const IPV4_SOCKET_ADDRESS_SOURCE: &str = r#"
fn foo() {
    let _ip = "192.168.1.1:8080";
}
"#;

pub(crate) const IPV6_SOCKET_ADDRESS_SOURCE: &str = r#"
fn foo() {
    let _ip = "[::1]:8080";
}
"#;

pub(crate) const X500_OID_SOURCE: &str = r#"
pub const OID: &str = "2.5.4.10";
"#;

pub(crate) const RUST_PATH_STRING_SOURCE: &str = r#"
pub const PATH: &str = "A::B::C::D::E::F";
"#;

pub(crate) const DOTTED_VERSION_SOURCE: &str = r#"
pub const VERSION: &str = "1.2.3.40";
"#;

pub(crate) const SHORT_STRING_SOURCE: &str = r#"
fn foo() {
    let _s = "hello";
}
"#;

pub(crate) const PEM_PRIVATE_KEY_SOURCE: &str = r#"
fn foo() {
    let _key = "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----";
}
"#;

pub(crate) const PROC_MACRO_ATTRIBUTE_SOURCE: &str = r#"
#[proc_macro]
fn my_macro(input: TokenStream) -> TokenStream {
    input
}
"#;

pub(crate) const PROC_MACRO_DERIVE_ATTRIBUTE_SOURCE: &str = r#"
#[proc_macro_derive(Foo)]
fn my_derive(input: TokenStream) -> TokenStream {
    input
}
"#;

pub(crate) const BUILD_SCRIPT_COMMAND_SOURCE: &str = r#"
use std::process::Command;

fn main() {
    Command::new("cc").status().unwrap();
}
"#;

pub(crate) const HEX_32_CHAR_SOURCE: &str = r#"
fn foo() {
    let _hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
}
"#;

pub(crate) const HEX_ODD_LENGTH_SOURCE: &str = r#"
fn foo() {
    let _odd = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2a";
}
"#;

pub(crate) const HEX_64_CHAR_MIXED_CASE_SOURCE: &str = r#"
fn foo() {
    let _key = "aAbBcCdDeEfF0011aAbBcCdDeEfF0011aAbBcCdDeEfF0011aAbBcCdDeEfF0011";
}
"#;

pub(crate) const BITCOIN_WIF_K_PREFIX_SOURCE: &str = r#"
fn foo() {
    let _key = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
}
"#;

pub(crate) const SHORT_BASE58_SOURCE: &str = r#"
fn foo() {
    let _addr = "1A1zP1eP5QGefi2DM";
}
"#;

pub(crate) const BASE58_WITH_INVALID_CHARS_SOURCE: &str = r#"
fn foo() {
    let _not_key = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVq0OIl";
}
"#;

pub(crate) const ETHEREUM_PRIVATE_KEY_SOURCE: &str = r#"
fn foo() {
    let _key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
}
"#;

pub(crate) const NEAR_ED25519_KEY_SOURCE: &str = r#"
fn foo() {
    let _key = "ed25519:3D4YudUahN1nawWogh6LMPvoRPW8QHr9AJsByJsXk7gn";
}
"#;

pub(crate) const GITHUB_PAT_SOURCE: &str = r#"
fn foo() {
    let _token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
}
"#;

pub(crate) const STRIPE_SECRET_KEY_SOURCE: &str = r#"
fn foo() {
    let _key = "sk_live_abcdefghijklmnopqrstuvwx";
}
"#;

pub(crate) const SHORT_0X_HEX_SOURCE: &str = r#"
fn foo() {
    let _val = "0xdeadbeef12";
}
"#;
