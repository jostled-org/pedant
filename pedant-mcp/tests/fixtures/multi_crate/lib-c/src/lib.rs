use std::net::TcpStream;
use ring::digest;

pub fn secure_connect() -> std::io::Result<TcpStream> {
    let _hash = digest::digest(&digest::SHA256, b"data");
    TcpStream::connect("127.0.0.1:443")
}
