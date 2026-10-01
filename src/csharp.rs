use libc::c_char;
use std::ffi::CStr;
use std::ffi::CString;
use std::panic::{catch_unwind, AssertUnwindSafe};

pub const MAX_FFI_STRING_LEN: usize = 64 * 1024;

#[derive(Debug)]
pub enum FfiStringError {
    Null,
    InvalidUtf8,
    TooLong,
}

pub fn rust_string_to_csharp_string_handle(s: String) -> *mut c_char {
    CString::new(s)
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

pub fn csharp_string_to_rust_string(s: *const c_char) -> Result<String, FfiStringError> {
    if s.is_null() {
        return Err(FfiStringError::Null);
    }

    // C callers must provide a readable, NUL-terminated string. A raw pointer alone cannot be
    // proven valid in portable Rust; managed callers meet this contract via UTF-8 marshaling.
    let c_str = unsafe { CStr::from_ptr(s) };
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

    // The pointer must have been returned by rust_string_to_csharp_string_handle and be freed
    // exactly once. SafeHandle enforces that lifetime for the supported .NET API.
    let _ = ffi_boundary(|| unsafe { drop(CString::from_raw(s)) }, ());
}
