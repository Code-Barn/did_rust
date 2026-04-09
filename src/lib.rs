use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

fn simple_rand() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u32)
        .unwrap_or(42)
}

#[no_mangle]
pub extern "C" fn generate_did_ffi(method_ptr: *const c_char) -> *mut c_char {
    if method_ptr.is_null() {
        return ptr::null_mut();
    }

    let method_cstr = unsafe { CStr::from_ptr(method_ptr) };
    let method_str = match method_cstr.to_str() {
        Ok(s) => s,
        Err(_) => "key",
    };

    let did = format!("did:{}:rust-{}", method_str, simple_rand());

    match CString::new(did) {
        Ok(c) => c.into_raw(),
        Err(_) => {
            let fallback = CString::new("did:key:error").expect("hardcoded string");
            fallback.into_raw()
        }
    }
}

#[no_mangle]
pub extern "C" fn verify_vc_ffi(vc_ptr: *const c_char) -> bool {
    if vc_ptr.is_null() {
        return false;
    }

    let vc_cstr = unsafe { CStr::from_ptr(vc_ptr) };
    match vc_cstr.to_str() {
        Ok(s) => !s.is_empty() && s.contains("credentialSubject"),
        Err(_) => false,
    }
}

#[no_mangle]
pub extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

#[no_mangle]
pub extern "C" fn issue_vc_ffi(
    credential_ptr: *const c_char,
    did_ptr: *const c_char,
    _key_ptr: *const c_char,
) -> *mut c_char {
    if credential_ptr.is_null() || did_ptr.is_null() {
        return ptr::null_mut();
    }

    let credential_cstr = unsafe { CStr::from_ptr(credential_ptr) };
    let did_cstr = unsafe { CStr::from_ptr(did_ptr) };

    let credential_str = match credential_cstr.to_str() {
        Ok(s) => s,
        Err(_) => "{}",
    };
    let did_str = match did_cstr.to_str() {
        Ok(s) => s,
        Err(_) => "did:key:error",
    };

    let result = format!(
        "{{\"vc\": {}, \"issuer\": \"{}\", \"issued\": true}}",
        credential_str, did_str
    );

    match CString::new(result) {
        Ok(c) => c.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}
