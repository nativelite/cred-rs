//! Platforms without a supported vault (Linux and other non-macOS Unix).
//!
//! The Secret Service API requires a D-Bus client, which is its own honest
//! chunk of work: planned, not faked. Until then every operation returns
//! `Unsupported`. Deliberately **no file fallback**: silently writing
//! secrets to disk in plaintext would betray exactly the promise this crate
//! exists to keep.

use std::io;

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "no OS credential vault backend on this platform yet \
         (Linux Secret Service needs D-Bus; planned). cred refuses to fall \
         back to plaintext files.",
    )
}

pub fn set(_service: &str, _name: &str, _secret: &[u8]) -> io::Result<()> {
    Err(unsupported())
}

pub fn get(_service: &str, _name: &str) -> io::Result<Option<Vec<u8>>> {
    Err(unsupported())
}

pub fn delete(_service: &str, _name: &str) -> io::Result<bool> {
    Err(unsupported())
}

pub fn entries(_service: &str) -> io::Result<Vec<String>> {
    Err(unsupported())
}
