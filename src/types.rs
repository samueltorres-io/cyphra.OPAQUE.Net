use crate::csharp;
use argon2::Argon2;
use libc::c_char;
use std::any::TypeId;
use std::collections::HashSet;
use std::sync::{Mutex, MutexGuard, OnceLock};
use zeroize::Zeroizing;

// Keyed by address *and* type: after a handle is freed its address can be reused by an allocation
// of another result type, and a stale pointer must not be able to free that one as the wrong type.
type Registry = HashSet<(usize, TypeId)>;

static LIVE_RESULT_HANDLES: OnceLock<Mutex<Registry>> = OnceLock::new();

fn live_result_handles() -> MutexGuard<'static, Registry> {
    csharp::lock_registry(LIVE_RESULT_HANDLES.get_or_init(Default::default))
}

pub fn into_result_handle<T: 'static>(value: T) -> *mut T {
    let ptr = Box::into_raw(Box::new(value));
    live_result_handles().insert((ptr as usize, TypeId::of::<T>()));
    ptr
}

fn release_result_handle<T: 'static>(ptr: *mut T) {
    if ptr.is_null() {
        return;
    }
    if live_result_handles().remove(&(ptr as usize, TypeId::of::<T>())) {
        csharp::ffi_boundary(|| unsafe { drop(Box::from_raw(ptr)) }, ());
    }
}

fn with_live_result_handle<T: 'static, R>(ptr: *mut T, action: impl FnOnce(&T) -> R) -> Option<R> {
    if ptr.is_null() {
        return None;
    }
    let handles = live_result_handles();
    if !handles.contains(&(ptr as usize, TypeId::of::<T>())) {
        return None;
    }
    // The registry lock is held until `action` returns, preventing concurrent release.
    Some(action(unsafe { &*ptr }))
}

macro_rules! result_string {
    ($ptr:expr, $field:ident) => {
        csharp::ffi_boundary(
            || {
                with_live_result_handle($ptr, |result| {
                    csharp::rust_string_to_csharp_string_handle(&result.$field)
                })
                .unwrap_or(std::ptr::null_mut())
            },
            std::ptr::null_mut(),
        )
    };
}

pub struct CustomIdentifiers {
    pub client: Option<String>,
    pub server: Option<String>,
}

impl CustomIdentifiers {
    pub fn new(client_param: Option<String>, server_param: Option<String>) -> CustomIdentifiers {
        CustomIdentifiers {
            client: client_param,
            server: server_param,
        }
    }
}

#[derive(Default)]
pub struct CustomKsf {
    pub argon: Argon2<'static>,
}

#[derive(Debug)]
pub enum KeyStretchingFunctionConfig {
    RfcDraftRecommended,
    MemoryConstrained,
    Custom {
        iterations: u32,
        memory: u32,
        parallelism: u32,
    },
}

pub struct CreateServerRegistrationResponseParams {
    pub server_setup: Zeroizing<String>,
    pub user_identifier: String,
    pub registration_request: Zeroizing<String>,
}

pub struct StartServerLoginParams {
    pub server_setup: Zeroizing<String>,
    pub registration_record: Option<Zeroizing<String>>,
    pub start_login_request: Zeroizing<String>,
    pub user_identifier: String,
    pub identifiers: Option<CustomIdentifiers>,
}

#[derive(Default)]
pub struct StartServerLoginResult {
    pub server_login_state: Zeroizing<String>,
    pub login_response: String,
}

#[no_mangle]
pub extern "C" fn get_start_server_login_response_state(
    ptr: *mut StartServerLoginResult,
) -> *const c_char {
    result_string!(ptr, server_login_state)
}

#[no_mangle]
pub extern "C" fn get_start_server_login_response_response(
    ptr: *mut StartServerLoginResult,
) -> *const c_char {
    result_string!(ptr, login_response)
}

#[no_mangle]
pub extern "C" fn free_start_server_login_result(ptr: *mut StartServerLoginResult) {
    if ptr.is_null() {
        return;
    }

    release_result_handle(ptr);
}

pub struct FinishServerLoginParams {
    pub server_login_state: Zeroizing<String>,
    pub finish_login_request: Zeroizing<String>,
}

#[derive(Default)]
pub struct StartClientLoginResult {
    pub client_login_state: Zeroizing<String>,
    pub start_login_request: String,
}

#[no_mangle]
pub extern "C" fn get_start_client_login_result_state(
    ptr: *mut StartClientLoginResult,
) -> *const c_char {
    result_string!(ptr, client_login_state)
}

#[no_mangle]
pub extern "C" fn get_start_client_login_result_request(
    ptr: *mut StartClientLoginResult,
) -> *const c_char {
    result_string!(ptr, start_login_request)
}

#[no_mangle]
pub extern "C" fn free_start_client_login_result(ptr: *mut StartClientLoginResult) {
    if ptr.is_null() {
        return;
    }

    release_result_handle(ptr);
}

pub struct FinishClientLoginParams {
    pub client_login_state: Zeroizing<String>,
    pub login_response: Zeroizing<String>,
    pub password: Zeroizing<String>,
    pub identifiers: Option<CustomIdentifiers>,
    pub key_stretching_function_config: KeyStretchingFunctionConfig,
}

#[derive(Default)]
pub struct FinishClientLoginResult {
    pub finish_login_request: String,
    pub session_key: Zeroizing<String>,
    pub export_key: Zeroizing<String>,
    pub server_static_public_key: String,
}

#[no_mangle]
pub extern "C" fn get_finish_client_login_result_request(
    ptr: *mut FinishClientLoginResult,
) -> *const c_char {
    result_string!(ptr, finish_login_request)
}

#[no_mangle]
pub extern "C" fn get_finish_client_login_result_session_key(
    ptr: *mut FinishClientLoginResult,
) -> *const c_char {
    result_string!(ptr, session_key)
}

#[no_mangle]
pub extern "C" fn get_finish_client_login_result_export_key(
    ptr: *mut FinishClientLoginResult,
) -> *const c_char {
    result_string!(ptr, export_key)
}

#[no_mangle]
pub extern "C" fn get_finish_client_login_result_public_key(
    ptr: *mut FinishClientLoginResult,
) -> *const c_char {
    result_string!(ptr, server_static_public_key)
}

#[no_mangle]
pub extern "C" fn free_finish_client_login_result(ptr: *mut FinishClientLoginResult) {
    if ptr.is_null() {
        return;
    }

    release_result_handle(ptr);
}

#[derive(Default)]
pub struct StartClientRegistrationResult {
    pub client_registration_state: Zeroizing<String>,
    pub registration_request: String,
}

#[no_mangle]
pub extern "C" fn get_start_client_registration_result_state(
    ptr: *mut StartClientRegistrationResult,
) -> *const c_char {
    result_string!(ptr, client_registration_state)
}

#[no_mangle]
pub extern "C" fn get_start_client_registration_result_request(
    ptr: *mut StartClientRegistrationResult,
) -> *const c_char {
    result_string!(ptr, registration_request)
}

#[no_mangle]
pub extern "C" fn free_start_client_registration_result(ptr: *mut StartClientRegistrationResult) {
    if ptr.is_null() {
        return;
    }

    release_result_handle(ptr);
}

pub struct FinishClientRegistrationParams {
    pub password: Zeroizing<String>,
    pub registration_response: Zeroizing<String>,
    pub client_registration_state: Zeroizing<String>,
    pub identifiers: Option<CustomIdentifiers>,
    pub key_stretching_function_config: KeyStretchingFunctionConfig,
}

#[derive(Default)]
pub struct FinishClientRegistrationResult {
    pub registration_record: String,
    pub export_key: Zeroizing<String>,
    pub server_static_public_key: String,
}

#[no_mangle]
pub extern "C" fn get_finish_client_registration_result_record(
    ptr: *mut FinishClientRegistrationResult,
) -> *const c_char {
    result_string!(ptr, registration_record)
}

#[no_mangle]
pub extern "C" fn get_finish_client_registration_result_export_key(
    ptr: *mut FinishClientRegistrationResult,
) -> *const c_char {
    result_string!(ptr, export_key)
}

#[no_mangle]
pub extern "C" fn get_finish_client_registration_result_public_key(
    ptr: *mut FinishClientRegistrationResult,
) -> *const c_char {
    result_string!(ptr, server_static_public_key)
}

#[no_mangle]
pub extern "C" fn free_finish_client_registration_result(ptr: *mut FinishClientRegistrationResult) {
    if ptr.is_null() {
        return;
    }

    release_result_handle(ptr);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Private types: the other tests run in parallel and allocate the real result types, so a
    // recycled address could otherwise be handed to them between a free and the next assertion.
    struct Probe(u8);
    #[allow(dead_code)]
    struct OtherProbe;

    #[test]
    fn registry_ignores_double_free_and_release_as_the_wrong_type() {
        let ptr = into_result_handle(Probe(7));
        assert_eq!(with_live_result_handle(ptr, |p| p.0), Some(7));

        // Same address, wrong type: a no-op, the live Probe must survive.
        release_result_handle::<OtherProbe>(ptr.cast());
        assert_eq!(with_live_result_handle(ptr, |p| p.0), Some(7));

        release_result_handle(ptr);
        assert_eq!(with_live_result_handle(ptr, |p| p.0), None);
        release_result_handle(ptr);
    }
}
