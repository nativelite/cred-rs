//! Integration tests for `cred`.
//!
//! On Windows these run against the *real* Credential Manager; every test
//! uses a unique service namespace and deletes what it wrote. On non-macOS
//! Unix (CI's ubuntu) the honest `Unsupported` contract is asserted
//! instead. macOS has no runner yet; its backend is compile-checked only.

#![allow(unused)]

fn svc(tag: &str) -> String {
    format!("nativelite-cred-test-{tag}-{}", std::process::id())
}

#[cfg(windows)]
mod windows_vault {
    use super::svc;

    #[test]
    fn round_trip_set_get_delete() {
        let s = svc("rt");
        cred::set(&s, "api-key", b"sk-example-123").unwrap();
        assert_eq!(
            cred::get(&s, "api-key").unwrap(),
            Some(b"sk-example-123".to_vec())
        );
        assert!(cred::delete(&s, "api-key").unwrap());
        assert_eq!(cred::get(&s, "api-key").unwrap(), None);
    }

    #[test]
    fn overwrite_replaces_the_secret() {
        let s = svc("ow");
        cred::set(&s, "k", b"first").unwrap();
        cred::set(&s, "k", b"second").unwrap();
        assert_eq!(cred::get(&s, "k").unwrap(), Some(b"second".to_vec()));
        assert!(cred::delete(&s, "k").unwrap());
    }

    #[test]
    fn missing_secret_is_none_and_delete_is_false() {
        let s = svc("miss");
        assert_eq!(cred::get(&s, "nope").unwrap(), None);
        assert!(!cred::delete(&s, "nope").unwrap());
    }

    #[test]
    fn binary_secrets_survive() {
        let s = svc("bin");
        let secret: Vec<u8> = (0u8..=255).collect();
        cred::set(&s, "blob", &secret).unwrap();
        assert_eq!(cred::get(&s, "blob").unwrap(), Some(secret));
        assert!(cred::delete(&s, "blob").unwrap());
    }

    #[test]
    fn entries_lists_names_under_the_service_only() {
        let s = svc("list");
        let other = svc("list-other");
        cred::set(&s, "alpha", b"1").unwrap();
        cred::set(&s, "beta", b"2").unwrap();
        cred::set(&other, "gamma", b"3").unwrap();
        assert_eq!(cred::entries(&s).unwrap(), vec!["alpha", "beta"]);
        assert!(cred::delete(&s, "alpha").unwrap());
        assert!(cred::delete(&s, "beta").unwrap());
        assert!(cred::delete(&other, "gamma").unwrap());
        assert!(cred::entries(&s).unwrap().is_empty());
    }

    #[test]
    fn max_size_secret_is_storable() {
        let s = svc("max");
        let secret = vec![0xAB; cred::MAX_SECRET];
        cred::set(&s, "big", &secret).unwrap();
        assert_eq!(cred::get(&s, "big").unwrap(), Some(secret));
        assert!(cred::delete(&s, "big").unwrap());
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod unsupported_contract {
    use super::svc;
    use std::io::ErrorKind;

    #[test]
    fn every_operation_is_honestly_unsupported() {
        let s = svc("unsup");
        assert_eq!(
            cred::set(&s, "k", b"v").unwrap_err().kind(),
            ErrorKind::Unsupported
        );
        assert_eq!(
            cred::get(&s, "k").unwrap_err().kind(),
            ErrorKind::Unsupported
        );
        assert_eq!(
            cred::delete(&s, "k").unwrap_err().kind(),
            ErrorKind::Unsupported
        );
        assert_eq!(
            cred::entries(&s).unwrap_err().kind(),
            ErrorKind::Unsupported
        );
    }

    #[test]
    fn validation_still_fires_before_the_backend() {
        // Bad input must be InvalidInput, not Unsupported: validation first.
        assert_eq!(
            cred::set("a/b", "k", b"v").unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
    }
}
