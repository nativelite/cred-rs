//! Windows Credential Manager, via our own advapi32 externs. Secrets are
//! generic credentials named `"{service}/{name}"`, persisted for the
//! current user on this machine.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;

#[repr(C)]
#[derive(Clone, Copy)]
struct Filetime {
    lo: u32,
    hi: u32,
}

#[repr(C)]
struct CredentialW {
    flags: u32,
    cred_type: u32,
    target_name: *mut u16,
    comment: *mut u16,
    last_written: Filetime,
    blob_size: u32,
    blob: *mut u8,
    persist: u32,
    attribute_count: u32,
    attributes: *mut c_void,
    target_alias: *mut u16,
    user_name: *mut u16,
}

#[link(name = "advapi32")]
extern "system" {
    fn CredWriteW(credential: *const CredentialW, flags: u32) -> i32;
    fn CredReadW(
        target: *const u16,
        cred_type: u32,
        flags: u32,
        credential: *mut *mut CredentialW,
    ) -> i32;
    fn CredDeleteW(target: *const u16, cred_type: u32, flags: u32) -> i32;
    fn CredEnumerateW(
        filter: *const u16,
        flags: u32,
        count: *mut u32,
        credentials: *mut *mut *mut CredentialW,
    ) -> i32;
    fn CredFree(buffer: *mut c_void);
}

const CRED_TYPE_GENERIC: u32 = 1;
const CRED_PERSIST_LOCAL_MACHINE: u32 = 2;
const ERROR_NOT_FOUND: i32 = 1168;

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain([0]).collect()
}

fn target_for(service: &str, name: &str) -> Vec<u16> {
    wide(&format!("{service}/{name}"))
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

fn not_found(err: &io::Error) -> bool {
    err.raw_os_error() == Some(ERROR_NOT_FOUND)
}

pub fn set(service: &str, name: &str, secret: &[u8]) -> io::Result<()> {
    let mut target = target_for(service, name);
    let mut user = wide("nativelite");
    let cred = CredentialW {
        flags: 0,
        cred_type: CRED_TYPE_GENERIC,
        target_name: target.as_mut_ptr(),
        comment: std::ptr::null_mut(),
        last_written: Filetime { lo: 0, hi: 0 },
        blob_size: secret.len() as u32,
        blob: secret.as_ptr() as *mut u8,
        persist: CRED_PERSIST_LOCAL_MACHINE,
        attribute_count: 0,
        attributes: std::ptr::null_mut(),
        target_alias: std::ptr::null_mut(),
        user_name: user.as_mut_ptr(),
    };
    if unsafe { CredWriteW(&cred, 0) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

pub fn get(service: &str, name: &str) -> io::Result<Option<Vec<u8>>> {
    let target = target_for(service, name);
    let mut pcred: *mut CredentialW = std::ptr::null_mut();
    if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut pcred) } == 0 {
        let err = last_error();
        return if not_found(&err) { Ok(None) } else { Err(err) };
    }
    let secret = unsafe {
        let c = &*pcred;
        let bytes = if c.blob.is_null() || c.blob_size == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(c.blob, c.blob_size as usize).to_vec()
        };
        CredFree(pcred as *mut c_void);
        bytes
    };
    Ok(Some(secret))
}

pub fn delete(service: &str, name: &str) -> io::Result<bool> {
    let target = target_for(service, name);
    if unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } == 0 {
        let err = last_error();
        return if not_found(&err) { Ok(false) } else { Err(err) };
    }
    Ok(true)
}

pub fn entries(service: &str) -> io::Result<Vec<String>> {
    let filter = wide(&format!("{service}/*"));
    let mut count: u32 = 0;
    let mut creds: *mut *mut CredentialW = std::ptr::null_mut();
    if unsafe { CredEnumerateW(filter.as_ptr(), 0, &mut count, &mut creds) } == 0 {
        let err = last_error();
        return if not_found(&err) {
            Ok(Vec::new())
        } else {
            Err(err)
        };
    }
    let prefix = format!("{service}/");
    let mut names = Vec::with_capacity(count as usize);
    unsafe {
        for i in 0..count as usize {
            let c = &**creds.add(i);
            if let Some(target) = read_wide(c.target_name) {
                if let Some(name) = target.strip_prefix(&prefix) {
                    names.push(name.to_string());
                }
            }
        }
        CredFree(creds as *mut c_void);
    }
    names.sort();
    Ok(names)
}

/// Read a NUL-terminated UTF-16 string (lossily) from a raw pointer.
unsafe fn read_wide(p: *const u16) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut len = 0;
    while *p.add(len) != 0 {
        len += 1;
    }
    let units = std::slice::from_raw_parts(p, len);
    Some(String::from_utf16_lossy(units))
}
