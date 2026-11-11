use libc::c_char;
use std::collections::HashSet;
use std::ffi::CStr;
use std::ffi::CString;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_FFI_STRING_LEN: usize = 64 * 1024;

static LIVE_STRING_HANDLES: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();

/// Locks a handle registry, recovering from poisoning. A panic while the guard is held cannot leave
/// a `HashSet` of addresses in a state that matters, whereas treating poison as fatal would make
/// every later call fail for the rest of the process.
pub fn lock_registry<T>(registry: &Mutex<T>) -> MutexGuard<'_, T> {
    registry.lock().unwrap_or_else(PoisonError::into_inner)
}

fn live_string_handles() -> MutexGuard<'static, HashSet<usize>> {
    lock_registry(LIVE_STRING_HANDLES.get_or_init(Default::default))
}

#[derive(Debug)]
pub enum FfiStringError {
    Null,
    InvalidUtf8,
    TooLong,
}

pub fn rust_string_to_csharp_string_handle(s: &str) -> *mut c_char {
    let Ok(value) = CString::new(s) else {
        return std::ptr::null_mut();
    };
    let ptr = CString::into_raw(value);
    live_string_handles().insert(ptr as usize);
    ptr
}

pub fn csharp_string_to_rust_string(s: *const c_char) -> Result<Zeroizing<String>, FfiStringError> {
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
    Ok(Zeroizing::new(value.to_owned()))
}

pub fn ffi_boundary<T>(action: impl FnOnce() -> T, fallback: T) -> T {
    catch_unwind(AssertUnwindSafe(action)).unwrap_or(fallback)
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }

    if live_string_handles().remove(&(s as usize)) {
        ffi_boundary(
            || {
                // Strings handed to C# may carry session keys or export keys: wipe before freeing.
                let mut bytes = unsafe { CString::from_raw(s) }.into_bytes();
                bytes.zeroize();
            },
            (),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_lock_survives_a_poisoning_panic() {
        let registry = Mutex::new(HashSet::from([1usize]));
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _guard = registry.lock().unwrap();
            panic!("poison the registry");
        }));
        assert!(registry.is_poisoned());

        let mut guard = lock_registry(&registry);
        guard.insert(2);
        assert!(guard.contains(&1) && guard.contains(&2));
    }
}
