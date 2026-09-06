# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-28

### Added
- `cred::set` / `get` / `delete` / `entries`: named secrets under a
  service namespace, stored in the OS-native credential vault via the
  crate's own FFI (no `keyring`/`libc`/`windows`/`security-framework`
  crates).
- Windows backend: Credential Manager generic credentials
  (`"{service}/{name}"`, advapi32), including service-scoped enumeration;
  integration-tested against the real vault.
- macOS backend: Keychain generic passwords via the classic `SecKeychain*`
  C API (compile-checked; no CI runner yet). `entries` unsupported there
  pending the `SecItem*` FFI surface.
- Non-macOS Unix: honest `ErrorKind::Unsupported` on every call; Secret
  Service needs D-Bus (planned). **No plaintext file fallback, by design.**
- Input validation (`InvalidInput` before any OS call): non-empty
  service/name, no `/`/NUL/control characters, `MAX_SECRET` (2560-byte)
  size cap.
- Stdlib-only `dev.py` runner (`check`, `test`, `fmt`, `guard`) and the
  Cargo.toml zero-dependency guard.

Fifth package in the nativelite **agent terminal** suite (see
`roadmap/agent-terminal-suite.md` in `nativelite/ops`).

[Unreleased]: https://github.com/nativelite/cred-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/nativelite/cred-rs/releases/tag/v0.1.0
