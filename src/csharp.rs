use libc::c_char;
use std::collections::HashSet;
use std::ffi::CStr;
use std::ffi::CString;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Mutex, OnceLock};

pub const MAX_FFI_STRING_LEN: usize = 64 * 1024;

static LIVE_STRING_HANDLES: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();

fn live_string_handles() -> &'static Mutex<HashSet<usize>> {
    LIVE_STRING_HANDLES.get_or_init(|| Mutex::new(HashSet::new()))
}

#[derive(Debug)]
pub enum FfiStringError {
    Null,
    InvalidUtf8,
    TooLong,
}

pub fn rust_string_to_csharp_string_handle(s: String) -> *mut c_char {
    let Ok(value) = CString::new(s) else {
        return std::ptr::null_mut();
    };
    let ptr = CString::into_raw(value);
    if let Ok(mut handles) = live_string_handles().lock() {
        handles.insert(ptr as usize);
        ptr
    } else {
        let _ = ffi_boundary(|| unsafe { drop(CString::from_raw(ptr)) }, ());
        std::ptr::null_mut()
    }
}

pub fn csharp_string_to_rust_string(s: *const c_char) -> Result<String, FfiStringError> {
    if s.is_null() {
        return Err(FfiStringError::Null);
    }

    // C callers must provide a readable pointer. A raw pointer alone cannot be proven valid in
    // portable Rust, but strnlen prevents an unterminated value from causing an unbounded scan.
    let len = unsafe { libc::strnlen(s, MAX_FFI_STRING_LEN + 1) };
    if len > MAX_FFI_STRING_LEN {
        return Err(FfiStringError::TooLong);
    }
    let bytes = unsafe { std::slice::from_raw_parts(s.cast::<u8>(), len + 1) };
    let c_str = CStr::from_bytes_with_nul(bytes).map_err(|_| FfiStringError::TooLong)?;
    let bytes = c_str.to_bytes();
    if bytes.len() > MAX_FFI_STRING_LEN {
        return Err(FfiStringError::TooLong);
    }
    let value = std::str::from_utf8(bytes).map_err(|_| FfiStringError::InvalidUtf8)?;
    Ok(value.to_owned())
}

pub fn ffi_boundary<T>(action: impl FnOnce() -> T, fallback: T) -> T {
    catch_unwind(AssertUnwindSafe(action)).unwrap_or(fallback)
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }

    let owned = live_string_handles()
        .lock()
        .map(|mut handles| handles.remove(&(s as usize)))
        .unwrap_or(false);
    if owned {
        let _ = ffi_boundary(|| unsafe { drop(CString::from_raw(s)) }, ());
    }
}
