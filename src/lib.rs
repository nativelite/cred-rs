//! cred — named secrets in the operating system's native credential vault,
//! on the Rust standard library alone. Zero dependencies, including no
//! `libc`/`windows`/`security-framework` crates: the OS boundary is this
//! crate's own small `extern` blocks.
//!
//! One concern: **bytes under names, in the vault the OS already guards.**
//! No key formats, no vendor semantics, no networking, and — deliberately —
//! no file fallback: a platform without a supported vault returns
//! [`std::io::ErrorKind::Unsupported`] instead of silently writing plaintext
//! to disk.
//!
//! ```no_run
//! cred::set("myapp", "api-key", b"sk-example-123")?;
//! assert_eq!(cred::get("myapp", "api-key")?, Some(b"sk-example-123".to_vec()));
//! cred::delete("myapp", "api-key")?;
//! # std::io::Result::Ok(())
//! ```
//!
//! Platform support:
//!
//! | OS | Backend | Status |
//! | --- | --- | --- |
//! | Windows | Credential Manager (`CredWriteW`/`CredReadW`/... in advapi32) | tested against the real vault |
//! | macOS | Keychain (`SecKeychain*` generic-password C API) | compile-checked; not yet CI-exercised |
//! | Linux / other Unix | Secret Service needs D-Bus — planned | `Unsupported` error, by design |
//!
//! Secrets are grouped by a `service` string (your application's namespace)
//! and identified by a `name` within it. On Windows the vault entry is the
//! generic credential `"{service}/{name}"`; on macOS it is a generic
//! password with `service`/`account`.

use std::io;

#[cfg(windows)]
#[path = "sys_windows.rs"]
mod sys;
#[cfg(target_os = "macos")]
#[path = "sys_macos.rs"]
mod sys;
#[cfg(all(unix, not(target_os = "macos")))]
#[path = "sys_unsupported.rs"]
mod sys;

/// The vault's per-secret size ceiling (Windows' generic-credential blob
/// limit, adopted on every platform for portability). Plenty for keys and
/// tokens; not a blob store.
pub const MAX_SECRET: usize = 2560;

/// Store `secret` under `service`/`name`, overwriting any previous value.
pub fn set(service: &str, name: &str, secret: &[u8]) -> io::Result<()> {
    validate(service, name)?;
    if secret.len() > MAX_SECRET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("secret exceeds {MAX_SECRET} bytes (the vault's limit)"),
        ));
    }
    sys::set(service, name, secret)
}

/// Read the secret under `service`/`name`; `Ok(None)` when absent.
pub fn get(service: &str, name: &str) -> io::Result<Option<Vec<u8>>> {
    validate(service, name)?;
    sys::get(service, name)
}

/// Delete the secret under `service`/`name`; returns whether it existed.
pub fn delete(service: &str, name: &str) -> io::Result<bool> {
    validate(service, name)?;
    sys::delete(service, name)
}

/// List the names stored under `service`.
///
/// Windows only for now (the Keychain's enumeration API is a different,
/// larger FFI surface); elsewhere this returns `Unsupported`. Callers that
/// need portable listing should keep their own index entry.
pub fn entries(service: &str) -> io::Result<Vec<String>> {
    validate(service, "x")?;
    sys::entries(service)
}

fn validate(service: &str, name: &str) -> io::Result<()> {
    let bad = |what: &str| {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{what} must be non-empty, without '/', NUL, or control characters"),
        ))
    };
    for (label, s) in [("service", service), ("name", name)] {
        if s.is_empty()
            || s.chars()
                .any(|c| c == '/' || (c as u32) < 0x20 || c == '\0')
        {
            return bad(label);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rejects_bad_names() {
        assert!(set("", "n", b"x").is_err());
        assert!(set("s", "", b"x").is_err());
        assert!(set("a/b", "n", b"x").is_err());
        assert!(set("s", "a/b", b"x").is_err());
        assert!(set("s", "a\nb", b"x").is_err());
        assert!(get("s\0", "n").is_err());
        assert!(delete("s", "\u{1}").is_err());
    }

    #[test]
    fn oversized_secret_rejected_before_reaching_the_os() {
        let big = vec![0u8; MAX_SECRET + 1];
        let err = set("svc", "name", &big).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
