//! Planted leak class: raw network I/O.

fn main() {
    let _stream = std::net::TcpStream::connect("127.0.0.1:8080");
}
