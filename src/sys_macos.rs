//! macOS Keychain, via our own Security.framework externs. Secrets are
//! generic-password items keyed by `service`/`account`.
//!
//! Uses the classic `SecKeychain*` C API, deprecated by Apple since 10.10
//! but stable, functional, and a fraction of the FFI surface of the
//! CoreFoundation-based `SecItem*` API. Compile-checked in CI; not yet
//! exercised by a macOS runner; treat as beta until it is.

use std::ffi::c_void;
use std::io;

#[link(name = "Security", kind = "framework")]
extern "C" {
    fn SecKeychainAddGenericPassword(
        keychain: *mut c_void,
        service_len: u32,
        service: *const u8,
        account_len: u32,
        account: *const u8,
        password_len: u32,
        password: *const u8,
        item: *mut *mut c_void,
    ) -> i32;
    fn SecKeychainFindGenericPassword(
        keychain: *const c_void,
        service_len: u32,
        service: *const u8,
        account_len: u32,
        account: *const u8,
        password_len: *mut u32,
        password: *mut *mut c_void,
        item: *mut *mut c_void,
    ) -> i32;
    fn SecKeychainItemModifyAttributesAndData(
        item: *mut c_void,
        attributes: *const c_void,
        length: u32,
        data: *const u8,
    ) -> i32;
    fn SecKeychainItemDelete(item: *mut c_void) -> i32;
    fn SecKeychainItemFreeContent(attributes: *mut c_void, data: *mut c_void) -> i32;
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFRelease(cf: *const c_void);
}

const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;

fn sec_err(status: i32) -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        format!("Security.framework error {status}"),
    )
}

pub fn set(service: &str, name: &str, secret: &[u8]) -> io::Result<()> {
    let status = unsafe {
        SecKeychainAddGenericPassword(
            std::ptr::null_mut(),
            service.len() as u32,
            service.as_ptr(),
            name.len() as u32,
            name.as_ptr(),
            secret.len() as u32,
            secret.as_ptr(),
            std::ptr::null_mut(),
        )
    };
    if status == 0 {
        return Ok(());
    }
    if status != ERR_SEC_DUPLICATE_ITEM {
        return Err(sec_err(status));
    }
    // Exists: find the item and replace its data.
    let mut item: *mut c_void = std::ptr::null_mut();
    let status = unsafe {
        SecKeychainFindGenericPassword(
            std::ptr::null(),
            service.len() as u32,
            service.as_ptr(),
            name.len() as u32,
            name.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut item,
        )
    };
    if status != 0 {
        return Err(sec_err(status));
    }
    let status = unsafe {
        let s = SecKeychainItemModifyAttributesAndData(
            item,
            std::ptr::null(),
            secret.len() as u32,
            secret.as_ptr(),
        );
        CFRelease(item);
        s
    };
    if status != 0 {
        return Err(sec_err(status));
    }
    Ok(())
}

pub fn get(service: &str, name: &str) -> io::Result<Option<Vec<u8>>> {
    let mut len: u32 = 0;
    let mut data: *mut c_void = std::ptr::null_mut();
    let status = unsafe {
        SecKeychainFindGenericPassword(
            std::ptr::null(),
            service.len() as u32,
            service.as_ptr(),
            name.len() as u32,
            name.as_ptr(),
            &mut len,
            &mut data,
            std::ptr::null_mut(),
        )
    };
    if status == ERR_SEC_ITEM_NOT_FOUND {
        return Ok(None);
    }
    if status != 0 {
        return Err(sec_err(status));
    }
    let secret = unsafe {
        let bytes = if data.is_null() || len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(data as *const u8, len as usize).to_vec()
        };
        SecKeychainItemFreeContent(std::ptr::null_mut(), data);
        bytes
    };
    Ok(Some(secret))
}

pub fn delete(service: &str, name: &str) -> io::Result<bool> {
    let mut item: *mut c_void = std::ptr::null_mut();
    let status = unsafe {
        SecKeychainFindGenericPassword(
            std::ptr::null(),
            service.len() as u32,
            service.as_ptr(),
            name.len() as u32,
            name.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut item,
        )
    };
    if status == ERR_SEC_ITEM_NOT_FOUND {
        return Ok(false);
    }
    if status != 0 {
        return Err(sec_err(status));
    }
    let status = unsafe {
        let s = SecKeychainItemDelete(item);
        CFRelease(item);
        s
    };
    if status != 0 {
        return Err(sec_err(status));
    }
    Ok(true)
}

pub fn entries(_service: &str) -> io::Result<Vec<String>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "listing keychain items needs the SecItemCopyMatching FFI surface; \
         planned. Keep an index entry if you need portable listing",
    ))
}
