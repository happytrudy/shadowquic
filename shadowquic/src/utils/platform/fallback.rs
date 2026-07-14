use socket2::Socket;
use std::io;

pub fn bind_device(_socket: &Socket, device_name: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("binding to interface {device_name:?} is unsupported on this platform"),
    ))
}
