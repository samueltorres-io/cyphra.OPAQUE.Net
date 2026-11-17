use libc::c_char;
use std::collections::HashSet;
use std::ffi::CString;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_FFI_STRING_LEN: usize = 64 * 1024;

static LIVE_STRING_HANDLES: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();

pub(crate) fn lock_registry<T>(registry: &Mutex<T>) -> MutexGuard<'_, T> {
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

    let len = unsafe { libc::strnlen(s, MAX_FFI_STRING_LEN + 1) };
    if len > MAX_FFI_STRING_LEN {
        return Err(FfiStringError::TooLong);
    }
    let bytes = unsafe { std::slice::from_raw_parts(s.cast::<u8>(), len) };
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
    fn accepts_exactly_the_maximum_length_and_rejects_one_more() {
        let mut at_max = vec![b'x'; MAX_FFI_STRING_LEN];
        at_max.push(0);
        let value = csharp_string_to_rust_string(at_max.as_ptr().cast()).unwrap();
        assert_eq!(value.len(), MAX_FFI_STRING_LEN);

        let mut over = vec![b'x'; MAX_FFI_STRING_LEN + 1];
        over.push(0);
        assert!(matches!(
            csharp_string_to_rust_string(over.as_ptr().cast()),
            Err(FfiStringError::TooLong)
        ));
    }

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
