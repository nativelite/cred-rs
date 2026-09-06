# cred-rs
**Named secrets in the operating system's native credential vault**, built
entirely on the Rust standard library. **Zero dependencies**: no `keyring`
crate tree, no `libc`/`windows`/`security-framework`. The OS boundary is
this crate's own small, audited `extern` blocks.

One concern: bytes under names, in the vault the OS already guards.

```rust,no_run
cred::set("myapp", "api-key", b"sk-example-123")?;
cred::get("myapp", "api-key")?;        // Some(b"sk-example-123".to_vec())
cred::entries("myapp")?;               // ["api-key"]        (Windows)
cred::delete("myapp", "api-key")?;     // true
# std::io::Result::Ok(())
```

Secrets are namespaced by a `service` string and identified by a `name`
within it. Size is capped at `MAX_SECRET` (2560 bytes, the Windows
generic-credential limit, adopted everywhere for portability): this is a
key/token store, not a blob store.

## Platform support, stated honestly

| OS | Backend | Status |
| --- | --- | --- |
| **Windows** | Credential Manager (`CredWriteW`/`CredReadW`/`CredDeleteW`/`CredEnumerateW`, advapi32) | **tested against the real vault** |
| **macOS** | Keychain (`SecKeychain*` generic-password C API, deprecated by Apple but stable; a fraction of the `SecItem*` FFI surface) | compile-checked; no macOS runner yet, so treat as beta |
| **Linux / other Unix** | Secret Service requires a D-Bus client: planned, not faked | every call returns `ErrorKind::Unsupported` |

**Deliberately no file fallback.** A platform without a supported vault gets
an honest `Unsupported` error. Silently writing secrets to plaintext files
would betray exactly the promise this crate exists to keep. `entries()` is
Windows-only for now (Keychain enumeration is a much larger FFI surface);
callers needing portable listing keep their own index entry.

## What's deliberately out of scope

- **Key formats and vendor semantics**: it stores bytes; what they mean is
  the caller's business (the `akey` app layers Anthropic-specific profiles
  on top).
- **Networking, caching, encryption of our own**: the OS vault is the
  security boundary; we add nothing beside it.

## Correctness

On Windows the integration tests run against the *real* Credential Manager:
set/get/delete round-trip, overwrite, a full 0–255 binary secret, the
exact `MAX_SECRET` boundary, service-scoped enumeration, each in a unique
per-process namespace, cleaned up afterward. On non-macOS Unix the tests
assert the `Unsupported` contract (and that input validation still fires
first with `InvalidInput`). Input validation rejects empty names, `/`, NUL,
and control characters before anything reaches the OS.

## Development

```bash
python dev.py check   # zero-dependency guard + cargo test (the pre-push gate)
python dev.py test    # cargo test
python dev.py fmt     # cargo fmt --check
python dev.py guard   # zero-dependency guard
```

`dev.py` is a stdlib-only runner, so `python dev.py check` is the same
one-command local gate used across every nativelite package. The guard fails
if `Cargo.toml` declares any dependency, runtime, build, or dev.
