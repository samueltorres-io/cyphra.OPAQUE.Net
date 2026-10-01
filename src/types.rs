use crate::csharp;
use argon2::Argon2;
use libc::c_char;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroizing;

static LIVE_RESULT_HANDLES: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();

fn live_result_handles() -> &'static Mutex<HashSet<usize>> {
    LIVE_RESULT_HANDLES.get_or_init(|| Mutex::new(HashSet::new()))
}

pub fn into_result_handle<T>(value: T) -> *mut T {
    let ptr = Box::into_raw(Box::new(value));
    if let Ok(mut handles) = live_result_handles().lock() {
        handles.insert(ptr as usize);
        ptr
    } else {
        // A poisoned registry is safer than releasing an untracked allocation to C.
        unsafe { drop(Box::from_raw(ptr)) };
        std::ptr::null_mut()
    }
}

fn release_result_handle<T>(ptr: *mut T) {
    if ptr.is_null() {
        return;
    }
    let owned = live_result_handles()
        .lock()
        .map(|mut handles| handles.remove(&(ptr as usize)))
        .unwrap_or(false);
    if owned {
        let _ = csharp::ffi_boundary(|| unsafe { drop(Box::from_raw(ptr)) }, ());
    }
}

fn with_live_result_handle<T, R>(ptr: *mut T, action: impl FnOnce(&T) -> R) -> Option<R> {
    if ptr.is_null() {
        return None;
    }
    let handles = live_result_handles().lock().ok()?;
    if !handles.contains(&(ptr as usize)) {
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
                    csharp::rust_string_to_csharp_string_handle(result.$field.clone())
                })
                .unwrap_or(std::ptr::null_mut())
            },
            std::ptr::null_mut(),
        )
    };
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub enum KeyStretchingFunctionConfig {
    #[serde(rename = "rfcDraftRecommended")]
    RfcDraftRecommended,
    #[serde(rename = "memoryConstrained")]
    MemoryConstrained,
    #[serde(rename = "custom")]
    Custom {
        #[serde(rename = "iterations")]
        iterations: u32,
        #[serde(rename = "memory")]
        memory: u32,
        #[serde(rename = "parallelism")]
        parallelism: u32,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateServerRegistrationResponseParams {
    #[serde(rename = "serverSetup")]
    pub server_setup: String,
    #[serde(rename = "userIdentifier")]
    pub user_identifier: String,
    #[serde(rename = "registrationRequest")]
    pub registration_request: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StartServerLoginParams {
    #[serde(rename = "serverSetup")]
    pub server_setup: String,
    #[serde(rename = "registrationRecord")]
    pub registration_record: Option<String>,
    #[serde(rename = "startLoginRequest")]
    pub start_login_request: String,
    #[serde(rename = "userIdentifier")]
    pub user_identifier: String,
    pub identifiers: Option<CustomIdentifiers>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StartServerLoginResult {
    #[serde(rename = "serverLoginState")]
    pub server_login_state: String,
    #[serde(rename = "loginResponse")]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct FinishServerLoginParams {
    #[serde(rename = "serverLoginState")]
    pub server_login_state: String,
    #[serde(rename = "finishLoginRequest")]
    pub finish_login_request: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StartClientLoginResult {
    #[serde(rename = "clientLoginState")]
    pub client_login_state: String,
    #[serde(rename = "startLoginRequest")]
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

#[derive(Debug)]
pub struct FinishClientLoginParams {
    pub client_login_state: String,
    pub login_response: String,
    pub password: Zeroizing<String>,
    pub identifiers: Option<CustomIdentifiers>,
    pub key_stretching_function_config: KeyStretchingFunctionConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FinishClientLoginResult {
    #[serde(rename = "finishLoginRequest")]
    pub finish_login_request: String,
    #[serde(rename = "sessionKey")]
    pub session_key: String,
    #[serde(rename = "exportKey")]
    pub export_key: String,
    #[serde(rename = "serverStaticPublicKey")]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct StartClientRegistrationResult {
    #[serde(rename = "clientRegistrationState")]
    pub client_registration_state: String,
    #[serde(rename = "registrationRequest")]
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

#[derive(Debug)]
pub struct FinishClientRegistrationParams {
    pub password: Zeroizing<String>,
    pub registration_response: String,
    pub client_registration_state: String,
    pub identifiers: Option<CustomIdentifiers>,
    pub key_stretching_function_config: KeyStretchingFunctionConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FinishClientRegistrationResult {
    #[serde(rename = "registrationRecord")]
    pub registration_record: String,
    #[serde(rename = "exportKey")]
    pub export_key: String,
    #[serde(rename = "serverStaticPublicKey")]
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
