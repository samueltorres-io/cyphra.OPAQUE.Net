use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::errors::{InternalError, ProtocolError};
use opaque_ke::ksf::Ksf;
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse, ServerLogin,
    ServerLoginStartParameters, ServerRegistration, ServerSetup,
};

use base64::{engine::general_purpose as b64, Engine as _};
use generic_array::{ArrayLength, GenericArray};
use zeroize::Zeroizing;

mod csharp;
mod seal;
use libc::c_char;

mod types;

// Deliberately payload-free: a cause attached here could reach callers and tell an attacker which
// protocol step rejected their input. The FFI boundary collapses every variant to an empty result.
enum Error {
    Protocol,
    Base64,
    InvalidKsf,
    InputTooLarge,
    Ffi,
}

fn protocol_error(_: ProtocolError) -> Error {
    Error::Protocol
}

struct DefaultCipherSuite;

#[cfg(not(feature = "p256"))]
impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = types::CustomKsf;
}

#[cfg(feature = "p256")]
impl CipherSuite for DefaultCipherSuite {
    type OprfCs = p256::NistP256;
    type KeGroup = p256::NistP256;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = types::CustomKsf;
}

const BASE64: b64::GeneralPurpose = b64::URL_SAFE_NO_PAD;
const MAX_ENCODED_PROTOCOL_MESSAGE_LEN: usize = 64 * 1024;
const MAX_PASSWORD_LEN: usize = 1024;
const MAX_IDENTIFIER_LEN: usize = 1024;
const MIN_CUSTOM_MEMORY_KIB: u32 = 64 * 1024;
// The RFC profile is an explicit caller-selected compatibility profile. Custom profiles are
// capped to a practical per-operation budget so untrusted application configuration cannot turn
// an authentication request into a multi-gigabyte allocation.
const MAX_CUSTOM_MEMORY_KIB: u32 = 256 * 1024;
const MAX_CUSTOM_ITERATIONS: u32 = 10;
const MAX_CUSTOM_PARALLELISM: u32 = 16;

type JsResult<T> = Result<T, Error>;

impl Ksf for types::CustomKsf {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        let mut output = GenericArray::default();
        self.argon
            .hash_password_into(&input, &[0; argon2::RECOMMENDED_SALT_LEN], &mut output)
            .map_err(|_| InternalError::KsfError)?;
        Ok(output)
    }
}

fn build_argon2_ksf(
    t_cost: u32,
    m_cost: u32,
    parallelism: u32,
) -> Result<Option<types::CustomKsf>, Error> {
    let mut param_builder = ParamsBuilder::default();
    param_builder.t_cost(t_cost);
    param_builder.m_cost(m_cost);
    param_builder.p_cost(parallelism);

    if let Ok(params) = param_builder.build() {
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        return Ok(Some(types::CustomKsf { argon }));
    }

    Err(Error::InvalidKsf)
}

fn get_custom_ksf(
    ksf_config: types::KeyStretchingFunctionConfig,
) -> Result<Option<types::CustomKsf>, Error> {
    match ksf_config {
        types::KeyStretchingFunctionConfig::RfcDraftRecommended => {
            build_argon2_ksf(1, u32::pow(2, 21) - 1, 4)
        }
        types::KeyStretchingFunctionConfig::MemoryConstrained => {
            build_argon2_ksf(3, u32::pow(2, 16), 4)
        }
        types::KeyStretchingFunctionConfig::Custom {
            iterations,
            memory,
            parallelism,
        } => {
            if !(1..=MAX_CUSTOM_ITERATIONS).contains(&iterations)
                || !(MIN_CUSTOM_MEMORY_KIB..=MAX_CUSTOM_MEMORY_KIB).contains(&memory)
                || !(1..=MAX_CUSTOM_PARALLELISM).contains(&parallelism)
            {
                return Err(Error::InvalidKsf);
            }
            build_argon2_ksf(iterations, memory, parallelism)
        }
    }
}

fn base64_decode(input: &str) -> JsResult<Zeroizing<Vec<u8>>> {
    if input.len() > MAX_ENCODED_PROTOCOL_MESSAGE_LEN {
        return Err(Error::InputTooLarge);
    }
    BASE64
        .decode(input)
        .map(Zeroizing::new)
        .map_err(|_| Error::Base64)
}

fn ffi_string(ptr: *const c_char) -> Result<Zeroizing<String>, Error> {
    csharp::csharp_string_to_rust_string(ptr).map_err(|_| Error::Ffi)
}

macro_rules! ffi_input {
    ($ptr:expr, $fallback:expr) => {{
        match ffi_string($ptr) {
            Ok(value) => value,
            Err(_) => return $fallback,
        }
    }};
}

fn checked_input(value: Zeroizing<String>, limit: usize) -> Result<String, Error> {
    if value.len() > limit {
        Err(Error::Ffi)
    } else {
        Ok(String::clone(&value))
    }
}

pub fn internal_create_server_setup() -> String {
    let mut rng: OsRng = OsRng;
    let setup = ServerSetup::<DefaultCipherSuite>::new(&mut rng);
    BASE64.encode(setup.serialize())
}

fn decode_server_setup(data: &str) -> JsResult<ServerSetup<DefaultCipherSuite>> {
    base64_decode(data).and_then(|bytes| {
        ServerSetup::<DefaultCipherSuite>::deserialize(&bytes).map_err(protocol_error)
    })
}

fn internal_get_server_public_key(data: &str) -> Result<String, Error> {
    let server_setup = decode_server_setup(data)?;
    let pub_key = server_setup.keypair().public().serialize();
    Ok(BASE64.encode(pub_key))
}

fn try_create_identifiers(
    csharp_client: *mut c_char,
    csharp_server: *mut c_char,
) -> Result<Option<types::CustomIdentifiers>, Error> {
    let rust_client = checked_input(ffi_string(csharp_client)?, MAX_IDENTIFIER_LEN)?;
    let rust_server = checked_input(ffi_string(csharp_server)?, MAX_IDENTIFIER_LEN)?;

    if rust_client.is_empty() && rust_server.is_empty() {
        return Ok(None);
    }

    let optional_rust_client: Option<String> = if rust_client.is_empty() {
        None
    } else {
        Some(rust_client)
    };

    let optional_rust_server: Option<String> = if rust_server.is_empty() {
        None
    } else {
        Some(rust_server)
    };

    Ok(Some(types::CustomIdentifiers::new(
        optional_rust_client,
        optional_rust_server,
    )))
}

fn try_create_ksf_config(
    csharp_config_type: *mut c_char,
    csharp_config_iterations: *mut c_char,
    csharp_config_memory: *mut c_char,
    csharp_config_parallelism: *mut c_char,
) -> Result<types::KeyStretchingFunctionConfig, Error> {
    let ksf_config_type = ffi_string(csharp_config_type)?;

    let ksf = match ksf_config_type.as_str() {
        "rfcDraftRecommended" => Ok(types::KeyStretchingFunctionConfig::RfcDraftRecommended),
        "memoryConstrained" => Ok(types::KeyStretchingFunctionConfig::MemoryConstrained),
        "custom" => {
            let iterations = ffi_string(csharp_config_iterations)?;
            if iterations.is_empty() {
                return Err(Error::InvalidKsf);
            }

            let memory = ffi_string(csharp_config_memory)?;
            if memory.is_empty() {
                return Err(Error::InvalidKsf);
            }

            let parallelism = ffi_string(csharp_config_parallelism)?;
            if parallelism.is_empty() {
                return Err(Error::InvalidKsf);
            }

            Ok(types::KeyStretchingFunctionConfig::Custom {
                iterations: iterations.parse().map_err(|_| Error::InvalidKsf)?,
                memory: memory.parse().map_err(|_| Error::InvalidKsf)?,
                parallelism: parallelism.parse().map_err(|_| Error::InvalidKsf)?,
            })
        }
        _ => Err(Error::InvalidKsf),
    };

    ksf
}

fn get_identifiers(idents: &Option<types::CustomIdentifiers>) -> Identifiers<'_> {
    Identifiers {
        client: idents
            .as_ref()
            .and_then(|idents| idents.client.as_ref().map(|val| val.as_bytes())),
        server: idents
            .as_ref()
            .and_then(|idents| idents.server.as_ref().map(|val| val.as_bytes())),
    }
}

fn internal_create_server_registration_response(
    params: types::CreateServerRegistrationResponseParams,
) -> Result<String, Error> {
    let server_setup = decode_server_setup(&params.server_setup)?;
    let registration_request_bytes = base64_decode(&params.registration_request)?;
    let registration_request =
        RegistrationRequest::deserialize(&registration_request_bytes).map_err(protocol_error)?;
    // opaque-ke ignores trailing bytes; require the canonical encoding like every other parser.
    if registration_request.serialize().len() != registration_request_bytes.len() {
        return Err(Error::Base64);
    }
    let server_registration_start_result = ServerRegistration::<DefaultCipherSuite>::start(
        &server_setup,
        registration_request,
        params.user_identifier.as_bytes(),
    )
    .map_err(protocol_error)?;
    let registration_response_bytes = server_registration_start_result.message.serialize();
    Ok(BASE64.encode(registration_response_bytes))
}

fn internal_start_server_login(
    params: types::StartServerLoginParams,
) -> Result<types::StartServerLoginResult, Error> {
    let server_setup = decode_server_setup(&params.server_setup)?;
    let registration_record_bytes = match params.registration_record {
        Some(pw) => base64_decode(&pw).map(Some),
        None => Ok(None),
    }?;
    let credential_request_bytes = base64_decode(&params.start_login_request)?;

    let mut rng: OsRng = OsRng;

    let registration_record = match registration_record_bytes.as_ref() {
        Some(bytes) => Some(
            ServerRegistration::<DefaultCipherSuite>::deserialize(bytes).map_err(protocol_error)?,
        ),
        None => None,
    };

    let start_params = ServerLoginStartParameters {
        identifiers: get_identifiers(&params.identifiers),
        context: None,
    };

    let server_login_start_result = ServerLogin::start(
        &mut rng,
        &server_setup,
        registration_record,
        CredentialRequest::deserialize(&credential_request_bytes).map_err(protocol_error)?,
        params.user_identifier.as_bytes(),
        start_params,
    )
    .map_err(protocol_error)?;

    let login_response = BASE64.encode(server_login_start_result.message.serialize());
    let server_login_state =
        Zeroizing::new(BASE64.encode(server_login_start_result.state.serialize()));

    Ok(types::StartServerLoginResult {
        server_login_state,
        login_response,
    })
}

fn internal_finish_server_login(
    params: types::FinishServerLoginParams,
) -> Result<Zeroizing<String>, Error> {
    let state_bytes = base64_decode(&params.server_login_state)?;
    finish_server_login_from_bytes(&state_bytes, &params.finish_login_request)
}

fn finish_server_login_from_bytes(
    state_bytes: &[u8],
    finish_login_request: &str,
) -> Result<Zeroizing<String>, Error> {
    let credential_finalization_bytes = base64_decode(finish_login_request)?;
    let state =
        ServerLogin::<DefaultCipherSuite>::deserialize(state_bytes).map_err(protocol_error)?;
    let server_login_finish_result = state
        .finish(
            CredentialFinalization::deserialize(&credential_finalization_bytes)
                .map_err(protocol_error)?,
        )
        .map_err(protocol_error)?;
    Ok(Zeroizing::new(
        BASE64.encode(server_login_finish_result.session_key),
    ))
}

/// Same as `internal_start_server_login`, but the returned state is sealed under `server_setup`.
fn internal_start_server_login_sealed(
    params: types::StartServerLoginParams,
    now: u64,
) -> Result<types::StartServerLoginResult, Error> {
    let setup_bytes = base64_decode(&params.server_setup)?;
    let mut result = internal_start_server_login(params)?;
    let raw_state = base64_decode(&result.server_login_state)?;
    let sealed = seal::seal(&setup_bytes, &raw_state, now).map_err(|_| Error::Ffi)?;
    result.server_login_state = Zeroizing::new(BASE64.encode(sealed));
    Ok(result)
}

fn internal_finish_server_login_sealed(
    server_setup: &str,
    sealed_state: &str,
    finish_login_request: &str,
    now: u64,
) -> Result<Zeroizing<String>, Error> {
    let setup_bytes = base64_decode(server_setup)?;
    let sealed = base64_decode(sealed_state)?;
    let state_bytes = seal::open(&setup_bytes, &sealed, now).map_err(|_| Error::Ffi)?;
    finish_server_login_from_bytes(&state_bytes, finish_login_request)
}

fn internal_start_client_login(
    password: Zeroizing<String>,
) -> Result<types::StartClientLoginResult, Error> {
    let mut client_rng = OsRng;
    let client_login_start_result =
        ClientLogin::<DefaultCipherSuite>::start(&mut client_rng, password.as_bytes())
            .map_err(protocol_error)?;

    Ok(types::StartClientLoginResult {
        client_login_state: Zeroizing::new(
            BASE64.encode(client_login_start_result.state.serialize()),
        ),
        start_login_request: BASE64.encode(client_login_start_result.message.serialize()),
    })
}

fn internal_finish_client_login(
    params: types::FinishClientLoginParams,
) -> Result<types::FinishClientLoginResult, Error> {
    let custom_ksf = get_custom_ksf(params.key_stretching_function_config)?;
    let credential_response_bytes = base64_decode(&params.login_response)?;
    let state_bytes = base64_decode(&params.client_login_state)?;
    let state =
        ClientLogin::<DefaultCipherSuite>::deserialize(&state_bytes).map_err(protocol_error)?;

    let finish_params = ClientLoginFinishParameters::new(
        None,
        get_identifiers(&params.identifiers),
        custom_ksf.as_ref(),
    );

    let result = state.finish(
        params.password.as_bytes(),
        CredentialResponse::deserialize(&credential_response_bytes).map_err(protocol_error)?,
        finish_params,
    );

    // A failed finish (wrong password, wrong identifiers, tampered response) is an expected
    // outcome, reported as an empty result rather than an error so the cause is not exposed.
    let Ok(client_login_finish_result) = result else {
        return Ok(types::FinishClientLoginResult::default());
    };

    Ok(types::FinishClientLoginResult {
        finish_login_request: BASE64.encode(client_login_finish_result.message.serialize()),
        session_key: Zeroizing::new(BASE64.encode(client_login_finish_result.session_key)),
        export_key: Zeroizing::new(BASE64.encode(client_login_finish_result.export_key)),
        server_static_public_key: BASE64.encode(client_login_finish_result.server_s_pk.serialize()),
    })
}

fn internal_start_client_registration(
    password: Zeroizing<String>,
) -> Result<types::StartClientRegistrationResult, Error> {
    let mut client_rng = OsRng;

    let client_registration_start_result =
        ClientRegistration::<DefaultCipherSuite>::start(&mut client_rng, password.as_bytes())
            .map_err(protocol_error)?;

    Ok(types::StartClientRegistrationResult {
        client_registration_state: Zeroizing::new(
            BASE64.encode(client_registration_start_result.state.serialize()),
        ),
        registration_request: BASE64.encode(client_registration_start_result.message.serialize()),
    })
}

fn internal_finish_client_registration(
    params: types::FinishClientRegistrationParams,
) -> Result<types::FinishClientRegistrationResult, Error> {
    let custom_ksf = get_custom_ksf(params.key_stretching_function_config)?;

    let registration_response_bytes = base64_decode(&params.registration_response)?;
    let mut rng: OsRng = OsRng;
    let client_registration = base64_decode(&params.client_registration_state)?;
    let state = ClientRegistration::<DefaultCipherSuite>::deserialize(&client_registration)
        .map_err(protocol_error)?;

    let finish_params = ClientRegistrationFinishParameters::new(
        get_identifiers(&params.identifiers),
        custom_ksf.as_ref(),
    );

    let client_finish_registration_result = state
        .finish(
            &mut rng,
            params.password.as_bytes(),
            RegistrationResponse::deserialize(&registration_response_bytes)
                .map_err(protocol_error)?,
            finish_params,
        )
        .map_err(protocol_error)?;

    let registration_record_bytes = client_finish_registration_result.message.serialize();

    Ok(types::FinishClientRegistrationResult {
        registration_record: BASE64.encode(registration_record_bytes),
        export_key: Zeroizing::new(BASE64.encode(client_finish_registration_result.export_key)),
        server_static_public_key: BASE64
            .encode(client_finish_registration_result.server_s_pk.serialize()),
    })
}

#[no_mangle]
pub extern "C" fn finish_client_registration(
    csharp_password: *mut c_char,
    csharp_registration_response: *mut c_char,
    csharp_client_registration_state: *mut c_char,
    csharp_client_identifier: *mut c_char,
    csharp_server_identifier: *mut c_char,
    csharp_config_type: *mut c_char,
    csharp_config_iterations: *mut c_char,
    csharp_config_memory: *mut c_char,
    csharp_config_parallelism: *mut c_char,
) -> *mut types::FinishClientRegistrationResult {
    csharp::ffi_boundary(
        || {
            let rust_password = ffi_input!(csharp_password, std::ptr::null_mut());
            if rust_password.len() > MAX_PASSWORD_LEN {
                return std::ptr::null_mut();
            }
            let rust_registration_response =
                ffi_input!(csharp_registration_response, std::ptr::null_mut());
            let rust_client_registration_state =
                ffi_input!(csharp_client_registration_state, std::ptr::null_mut());
            let identifiers =
                match try_create_identifiers(csharp_client_identifier, csharp_server_identifier) {
                    Ok(value) => value,
                    Err(_) => return std::ptr::null_mut(),
                };

            let ksf_config = try_create_ksf_config(
                csharp_config_type,
                csharp_config_iterations,
                csharp_config_memory,
                csharp_config_parallelism,
            );

            match ksf_config {
                Ok(v) => {
                    if let Ok(result) =
                        internal_finish_client_registration(types::FinishClientRegistrationParams {
                            password: rust_password,
                            registration_response: rust_registration_response,
                            client_registration_state: rust_client_registration_state,
                            identifiers,
                            key_stretching_function_config: v,
                        })
                    {
                        return types::into_result_handle(result);
                    }

                    types::into_result_handle(types::FinishClientRegistrationResult::default())
                }
                Err(_) => {
                    types::into_result_handle(types::FinishClientRegistrationResult::default())
                }
            }
        },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub extern "C" fn create_server_setup() -> *mut c_char {
    csharp::ffi_boundary(
        || csharp::rust_string_to_csharp_string_handle(&internal_create_server_setup()),
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub extern "C" fn get_server_public_key(data: *mut c_char) -> *mut c_char {
    csharp::ffi_boundary(
        || {
            let secret = ffi_input!(data, std::ptr::null_mut());
            if let Ok(public_key) = internal_get_server_public_key(&secret) {
                return csharp::rust_string_to_csharp_string_handle(&public_key);
            }

            csharp::rust_string_to_csharp_string_handle("")
        },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub extern "C" fn create_server_registration_response(
    csharp_server_setup: *mut c_char,
    csharp_user_identifier: *mut c_char,
    csharp_registration_request: *mut c_char,
) -> *mut c_char {
    csharp::ffi_boundary(
        || {
            let rust_server_setup = ffi_input!(csharp_server_setup, std::ptr::null_mut());
            let rust_user_identifier = ffi_input!(csharp_user_identifier, std::ptr::null_mut());
            if rust_user_identifier.len() > MAX_IDENTIFIER_LEN {
                return std::ptr::null_mut();
            }
            let rust_registration_request =
                ffi_input!(csharp_registration_request, std::ptr::null_mut());

            if let Ok(result) = internal_create_server_registration_response(
                types::CreateServerRegistrationResponseParams {
                    server_setup: rust_server_setup,
                    user_identifier: String::clone(&rust_user_identifier),
                    registration_request: rust_registration_request,
                },
            ) {
                return csharp::rust_string_to_csharp_string_handle(&result);
            }

            csharp::rust_string_to_csharp_string_handle("")
        },
        std::ptr::null_mut(),
    )
}

fn start_server_login_impl(
    sealed: bool,
    csharp_server_setup: *mut c_char,
    csharp_start_login_request: *mut c_char,
    csharp_user_identifier: *mut c_char,
    csharp_registration_record: *mut c_char,
    csharp_client_identifier: *mut c_char,
    csharp_server_identifier: *mut c_char,
) -> *mut types::StartServerLoginResult {
    csharp::ffi_boundary(
        || {
            let rust_server_setup = ffi_input!(csharp_server_setup, std::ptr::null_mut());
            let rust_start_login_request =
                ffi_input!(csharp_start_login_request, std::ptr::null_mut());
            let rust_user_identifier = ffi_input!(csharp_user_identifier, std::ptr::null_mut());
            if rust_user_identifier.len() > MAX_IDENTIFIER_LEN {
                return std::ptr::null_mut();
            }

            let potentially_empty_registration_record =
                ffi_input!(csharp_registration_record, std::ptr::null_mut());
            let rust_registration_record: Option<Zeroizing<String>> =
                if potentially_empty_registration_record.is_empty() {
                    None
                } else {
                    Some(potentially_empty_registration_record)
                };

            let identifiers =
                match try_create_identifiers(csharp_client_identifier, csharp_server_identifier) {
                    Ok(value) => value,
                    Err(_) => return std::ptr::null_mut(),
                };

            let params = types::StartServerLoginParams {
                server_setup: rust_server_setup,
                registration_record: rust_registration_record,
                start_login_request: rust_start_login_request,
                user_identifier: String::clone(&rust_user_identifier),
                identifiers,
            };
            let started = if sealed {
                internal_start_server_login_sealed(params, seal::unix_now())
            } else {
                internal_start_server_login(params)
            };
            if let Ok(result) = started {
                return types::into_result_handle(result);
            }

            types::into_result_handle(types::StartServerLoginResult::default())
        },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub extern "C" fn start_server_login(
    csharp_server_setup: *mut c_char,
    csharp_start_login_request: *mut c_char,
    csharp_user_identifier: *mut c_char,
    csharp_registration_record: *mut c_char,
    csharp_client_identifier: *mut c_char,
    csharp_server_identifier: *mut c_char,
) -> *mut types::StartServerLoginResult {
    start_server_login_impl(
        false,
        csharp_server_setup,
        csharp_start_login_request,
        csharp_user_identifier,
        csharp_registration_record,
        csharp_client_identifier,
        csharp_server_identifier,
    )
}

#[no_mangle]
pub extern "C" fn start_server_login_sealed(
    csharp_server_setup: *mut c_char,
    csharp_start_login_request: *mut c_char,
    csharp_user_identifier: *mut c_char,
    csharp_registration_record: *mut c_char,
    csharp_client_identifier: *mut c_char,
    csharp_server_identifier: *mut c_char,
) -> *mut types::StartServerLoginResult {
    start_server_login_impl(
        true,
        csharp_server_setup,
        csharp_start_login_request,
        csharp_user_identifier,
        csharp_registration_record,
        csharp_client_identifier,
        csharp_server_identifier,
    )
}

#[no_mangle]
pub extern "C" fn finish_server_login(
    csharp_server_login_state: *mut c_char,
    csharp_finish_login_request: *mut c_char,
) -> *mut c_char {
    csharp::ffi_boundary(
        || {
            let rust_server_login_state =
                ffi_input!(csharp_server_login_state, std::ptr::null_mut());
            let rust_finish_login_request =
                ffi_input!(csharp_finish_login_request, std::ptr::null_mut());

            if let Ok(result) = internal_finish_server_login(types::FinishServerLoginParams {
                server_login_state: rust_server_login_state,
                finish_login_request: rust_finish_login_request,
            }) {
                return csharp::rust_string_to_csharp_string_handle(&result);
            }

            csharp::rust_string_to_csharp_string_handle("")
        },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub extern "C" fn finish_server_login_sealed(
    csharp_server_setup: *mut c_char,
    csharp_sealed_login_state: *mut c_char,
    csharp_finish_login_request: *mut c_char,
) -> *mut c_char {
    csharp::ffi_boundary(
        || {
            let rust_server_setup = ffi_input!(csharp_server_setup, std::ptr::null_mut());
            let rust_sealed_state = ffi_input!(csharp_sealed_login_state, std::ptr::null_mut());
            let rust_finish_login_request =
                ffi_input!(csharp_finish_login_request, std::ptr::null_mut());

            if let Ok(result) = internal_finish_server_login_sealed(
                &rust_server_setup,
                &rust_sealed_state,
                &rust_finish_login_request,
                seal::unix_now(),
            ) {
                return csharp::rust_string_to_csharp_string_handle(&result);
            }

            csharp::rust_string_to_csharp_string_handle("")
        },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub extern "C" fn start_client_login(
    csharp_password: *mut c_char,
) -> *mut types::StartClientLoginResult {
    csharp::ffi_boundary(
        || {
            let rust_password = ffi_input!(csharp_password, std::ptr::null_mut());
            if rust_password.len() > MAX_PASSWORD_LEN {
                return std::ptr::null_mut();
            }
            if let Ok(result) = internal_start_client_login(rust_password) {
                return types::into_result_handle(result);
            }

            types::into_result_handle(types::StartClientLoginResult::default())
        },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub extern "C" fn finish_client_login(
    csharp_client_login_state: *mut c_char,
    csharp_login_response: *mut c_char,
    csharp_password: *mut c_char,
    csharp_client_identifier: *mut c_char,
    csharp_server_identifier: *mut c_char,
    csharp_config_type: *mut c_char,
    csharp_config_iterations: *mut c_char,
    csharp_config_memory: *mut c_char,
    csharp_config_parallelism: *mut c_char,
) -> *mut types::FinishClientLoginResult {
    csharp::ffi_boundary(
        || {
            let rust_client_login_state =
                ffi_input!(csharp_client_login_state, std::ptr::null_mut());
            let rust_login_response = ffi_input!(csharp_login_response, std::ptr::null_mut());
            let rust_password = ffi_input!(csharp_password, std::ptr::null_mut());
            if rust_password.len() > MAX_PASSWORD_LEN {
                return std::ptr::null_mut();
            }
            let identifiers =
                match try_create_identifiers(csharp_client_identifier, csharp_server_identifier) {
                    Ok(value) => value,
                    Err(_) => return std::ptr::null_mut(),
                };

            let ksf_config = try_create_ksf_config(
                csharp_config_type,
                csharp_config_iterations,
                csharp_config_memory,
                csharp_config_parallelism,
            );

            match ksf_config {
                Ok(v) => {
                    if let Ok(result) =
                        internal_finish_client_login(types::FinishClientLoginParams {
                            client_login_state: rust_client_login_state,
                            login_response: rust_login_response,
                            password: rust_password,
                            identifiers,
                            key_stretching_function_config: v,
                        })
                    {
                        return types::into_result_handle(result);
                    }

                    types::into_result_handle(types::FinishClientLoginResult::default())
                }
                Err(_) => types::into_result_handle(types::FinishClientLoginResult::default()),
            }
        },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub extern "C" fn start_client_registration(
    csharp_password: *mut c_char,
) -> *mut types::StartClientRegistrationResult {
    csharp::ffi_boundary(
        || {
            let rust_password = ffi_input!(csharp_password, std::ptr::null_mut());
            if rust_password.len() > MAX_PASSWORD_LEN {
                return std::ptr::null_mut();
            }
            if let Ok(result) = internal_start_client_registration(rust_password) {
                return types::into_result_handle(result);
            }

            types::into_result_handle(types::StartClientRegistrationResult::default())
        },
        std::ptr::null_mut(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn custom_ksf(
        iterations: u32,
        memory: u32,
        parallelism: u32,
    ) -> types::KeyStretchingFunctionConfig {
        types::KeyStretchingFunctionConfig::Custom {
            iterations,
            memory,
            parallelism,
        }
    }

    #[test]
    fn rejects_malformed_base64() {
        assert!(base64_decode("%%%not-base64%%%").is_err());
    }

    #[test]
    fn enforces_encoded_message_size_limit() {
        let allowed = "A".repeat(MAX_ENCODED_PROTOCOL_MESSAGE_LEN);
        let oversized = "A".repeat(MAX_ENCODED_PROTOCOL_MESSAGE_LEN + 1);

        assert!(base64_decode(&allowed).is_ok());
        assert!(base64_decode(&oversized).is_err());
    }

    #[test]
    fn rejects_unsafe_custom_ksf_parameters() {
        assert!(get_custom_ksf(custom_ksf(0, MIN_CUSTOM_MEMORY_KIB, 1)).is_err());
        assert!(get_custom_ksf(custom_ksf(1, MIN_CUSTOM_MEMORY_KIB - 1, 1)).is_err());
        assert!(get_custom_ksf(custom_ksf(1, MAX_CUSTOM_MEMORY_KIB + 1, 1)).is_err());
        assert!(get_custom_ksf(custom_ksf(1, MIN_CUSTOM_MEMORY_KIB, 0)).is_err());
        assert!(get_custom_ksf(custom_ksf(
            1,
            MIN_CUSTOM_MEMORY_KIB,
            MAX_CUSTOM_PARALLELISM + 1
        ))
        .is_err());
    }

    #[test]
    fn accepts_bounded_custom_ksf_parameters() {
        assert!(get_custom_ksf(custom_ksf(1, MIN_CUSTOM_MEMORY_KIB, 1)).is_ok());
        assert!(get_custom_ksf(custom_ksf(
            MAX_CUSTOM_ITERATIONS,
            MAX_CUSTOM_MEMORY_KIB,
            MAX_CUSTOM_PARALLELISM,
        ))
        .is_ok());
    }

    #[test]
    fn rejects_non_numeric_ffi_ksf_parameters() {
        let kind = CString::new("custom").expect("static test input is valid");
        let iterations = CString::new("not-a-number").expect("static test input is valid");
        let memory =
            CString::new(MIN_CUSTOM_MEMORY_KIB.to_string()).expect("numeric input is valid");
        let parallelism = CString::new("1").expect("static test input is valid");

        assert!(try_create_ksf_config(
            kind.as_ptr() as *mut c_char,
            iterations.as_ptr() as *mut c_char,
            memory.as_ptr() as *mut c_char,
            parallelism.as_ptr() as *mut c_char,
        )
        .is_err());
    }

    #[test]
    fn rejects_null_and_invalid_utf8_ffi_input() {
        assert!(ffi_string(std::ptr::null()).is_err());
        let invalid = [0xff_u8, 0];
        assert!(ffi_string(invalid.as_ptr() as *const c_char).is_err());
        let unterminated = vec![b'x'; csharp::MAX_FFI_STRING_LEN + 1];
        assert!(ffi_string(unterminated.as_ptr() as *const c_char).is_err());
    }

    #[test]
    fn rejects_oversized_password_before_protocol_processing() {
        let password = CString::new("x".repeat(MAX_PASSWORD_LEN + 1)).unwrap();
        assert!(start_client_login(password.as_ptr() as *mut c_char).is_null());
    }

    #[test]
    fn result_handles_ignore_double_free() {
        let password = CString::new("password").unwrap();
        let result = start_client_login(password.as_ptr() as *mut c_char);
        assert!(!result.is_null());
        types::free_start_client_login_result(result);
        types::free_start_client_login_result(result);
    }

    #[test]
    fn string_handles_ignore_double_free() {
        let handle = csharp::rust_string_to_csharp_string_handle("test");
        assert!(!handle.is_null());
        csharp::free_string(handle);
        csharp::free_string(handle);
    }

    // ---- protocol round trip and adversarial inputs, driven through the internal API ----

    const USER: &str = "user@example.test";
    const PASSWORD: &str = "correct horse battery staple";

    fn z(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_owned())
    }

    fn ksf() -> types::KeyStretchingFunctionConfig {
        // Smallest accepted profile keeps the suite fast.
        custom_ksf(1, MIN_CUSTOM_MEMORY_KIB, 1)
    }

    struct Registered {
        setup: String,
        record: String,
        export_key: Zeroizing<String>,
    }

    fn register(password: &str) -> Registered {
        let setup = internal_create_server_setup();
        let start = internal_start_client_registration(z(password))
            .ok()
            .unwrap();
        let response = internal_create_server_registration_response(
            types::CreateServerRegistrationResponseParams {
                server_setup: z(&setup),
                user_identifier: USER.to_owned(),
                registration_request: z(&start.registration_request),
            },
        )
        .ok()
        .unwrap();
        let finish = internal_finish_client_registration(types::FinishClientRegistrationParams {
            password: z(password),
            registration_response: z(&response),
            client_registration_state: start.client_registration_state.clone(),
            identifiers: None,
            key_stretching_function_config: ksf(),
        })
        .ok()
        .unwrap();
        Registered {
            setup,
            record: finish.registration_record,
            export_key: finish.export_key,
        }
    }

    fn server_start(
        reg: &Registered,
        request: &str,
        record: Option<&str>,
    ) -> JsResult<types::StartServerLoginResult> {
        internal_start_server_login(types::StartServerLoginParams {
            server_setup: z(&reg.setup),
            registration_record: record.map(z),
            start_login_request: z(request),
            user_identifier: USER.to_owned(),
            identifiers: None,
        })
    }

    fn client_finish(
        state: &Zeroizing<String>,
        response: &str,
        password: &str,
    ) -> types::FinishClientLoginResult {
        internal_finish_client_login(types::FinishClientLoginParams {
            client_login_state: state.clone(),
            login_response: z(response),
            password: z(password),
            identifiers: None,
            key_stretching_function_config: ksf(),
        })
        .ok()
        .unwrap()
    }

    fn server_finish(state: &str, finalization: &str) -> JsResult<Zeroizing<String>> {
        internal_finish_server_login(types::FinishServerLoginParams {
            server_login_state: z(state),
            finish_login_request: z(finalization),
        })
    }

    #[test]
    fn full_round_trip_agrees_on_session_and_export_keys() {
        let reg = register(PASSWORD);
        let start = internal_start_client_login(z(PASSWORD)).ok().unwrap();
        let server = server_start(&reg, &start.start_login_request, Some(&reg.record))
            .ok()
            .unwrap();
        let client = client_finish(&start.client_login_state, &server.login_response, PASSWORD);

        assert!(!client.finish_login_request.is_empty());
        assert_eq!(*client.export_key, *reg.export_key);
        let server_key = server_finish(&server.server_login_state, &client.finish_login_request)
            .ok()
            .unwrap();
        assert_eq!(*server_key, *client.session_key);
    }

    #[test]
    fn wrong_password_yields_empty_result_without_secrets() {
        let reg = register(PASSWORD);
        let start = internal_start_client_login(z("not the password"))
            .ok()
            .unwrap();
        let server = server_start(&reg, &start.start_login_request, Some(&reg.record))
            .ok()
            .unwrap();
        let client = client_finish(
            &start.client_login_state,
            &server.login_response,
            "not the password",
        );

        assert!(client.finish_login_request.is_empty());
        assert!(client.session_key.is_empty());
        assert!(client.export_key.is_empty());
        assert!(client.server_static_public_key.is_empty());
    }

    #[test]
    fn unknown_user_still_gets_a_response_but_cannot_finish() {
        // No record: the server answers with a dummy so existence is not revealed at this step.
        let reg = register(PASSWORD);
        let start = internal_start_client_login(z(PASSWORD)).ok().unwrap();
        let server = server_start(&reg, &start.start_login_request, None)
            .ok()
            .unwrap();
        assert!(!server.login_response.is_empty());
        let client = client_finish(&start.client_login_state, &server.login_response, PASSWORD);
        assert!(client.session_key.is_empty());
    }

    #[test]
    fn server_rejects_a_finalization_from_another_session() {
        let reg = register(PASSWORD);
        let run = || {
            let start = internal_start_client_login(z(PASSWORD)).ok().unwrap();
            let server = server_start(&reg, &start.start_login_request, Some(&reg.record))
                .ok()
                .unwrap();
            let client = client_finish(&start.client_login_state, &server.login_response, PASSWORD);
            (server, client)
        };
        let (server_a, _client_a) = run();
        let (_server_b, client_b) = run();

        // Replay / cross-session: B's finalization must not complete A's login.
        assert!(
            server_finish(&server_a.server_login_state, &client_b.finish_login_request).is_err()
        );
    }

    #[test]
    fn tampered_messages_are_rejected_not_accepted() {
        let reg = register(PASSWORD);
        let start = internal_start_client_login(z(PASSWORD)).ok().unwrap();
        let server = server_start(&reg, &start.start_login_request, Some(&reg.record))
            .ok()
            .unwrap();
        let client = client_finish(&start.client_login_state, &server.login_response, PASSWORD);

        let flip = |s: &str| {
            let mut bytes = BASE64.decode(s).unwrap();
            let mid = bytes.len() / 2;
            bytes[mid] ^= 0x01;
            BASE64.encode(bytes)
        };

        // Flipped finalization MAC.
        assert!(server_finish(
            &server.server_login_state,
            &flip(&client.finish_login_request)
        )
        .is_err());
        // Flipped server response: client must not derive keys.
        let tampered = client_finish(
            &start.client_login_state,
            &flip(&server.login_response),
            PASSWORD,
        );
        assert!(tampered.session_key.is_empty());
    }

    #[test]
    fn hostile_garbage_never_panics_or_succeeds() {
        let reg = register(PASSWORD);
        // Deterministic xorshift: reproducible, no extra dependency.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for len in (0..300).step_by(7) {
            let garbage: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let g = BASE64.encode(&garbage);
            assert!(server_start(&reg, &g, Some(&reg.record)).is_err());
            assert!(server_start(&reg, &g, Some(&g)).is_err());
            assert!(server_finish(&g, &g).is_err());
            assert!(internal_get_server_public_key(&g).is_err());
            assert!(
                internal_finish_client_login(types::FinishClientLoginParams {
                    client_login_state: z(&g),
                    login_response: z(&g),
                    password: z(PASSWORD),
                    identifiers: None,
                    key_stretching_function_config: ksf(),
                })
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_non_base64_and_empty_protocol_input() {
        let reg = register(PASSWORD);
        assert!(server_start(&reg, "", Some(&reg.record)).is_err());
        assert!(server_start(&reg, "!!!", Some(&reg.record)).is_err());
        assert!(internal_get_server_public_key("").is_err());
    }

    // ---- FFI boundary ----

    #[test]
    fn ffi_boundary_contains_panics() {
        let value = csharp::ffi_boundary(|| -> i32 { panic!("boom") }, 7);
        assert_eq!(value, 7);
    }

    #[test]
    fn extern_entry_points_return_null_or_empty_for_hostile_pointers() {
        let null = std::ptr::null_mut::<c_char>();
        assert!(start_client_registration(null).is_null());
        assert!(start_client_login(null).is_null());
        assert!(get_server_public_key(null).is_null());
        assert!(create_server_registration_response(null, null, null).is_null());
        assert!(start_server_login(null, null, null, null, null, null).is_null());
        assert!(finish_server_login(null, null).is_null());
        assert!(
            finish_client_login(null, null, null, null, null, null, null, null, null).is_null()
        );
        assert!(
            finish_client_registration(null, null, null, null, null, null, null, null, null)
                .is_null()
        );
    }

    #[test]
    fn rejects_oversized_identifier_before_protocol_processing() {
        let setup = CString::new(internal_create_server_setup()).unwrap();
        let user = CString::new("u".repeat(MAX_IDENTIFIER_LEN + 1)).unwrap();
        let request = CString::new("AAAA").unwrap();
        assert!(create_server_registration_response(
            setup.as_ptr() as *mut c_char,
            user.as_ptr() as *mut c_char,
            request.as_ptr() as *mut c_char,
        )
        .is_null());
    }

    #[test]
    fn registration_request_must_be_exact_length() {
        let setup = internal_create_server_setup();
        let start = internal_start_client_registration(z("pw")).ok().unwrap();
        let mut bytes = BASE64.decode(&start.registration_request).unwrap();
        let call = |b: &[u8]| {
            internal_create_server_registration_response(
                types::CreateServerRegistrationResponseParams {
                    server_setup: z(&setup),
                    user_identifier: USER.to_owned(),
                    registration_request: z(&BASE64.encode(b)),
                },
            )
        };
        assert!(call(&bytes).is_ok());
        bytes.push(0);
        assert!(call(&bytes).is_err());
    }

    fn sealed_start(reg: &Registered, request: &str, now: u64) -> types::StartServerLoginResult {
        internal_start_server_login_sealed(
            types::StartServerLoginParams {
                server_setup: z(&reg.setup),
                registration_record: Some(z(&reg.record)),
                start_login_request: z(request),
                user_identifier: USER.to_owned(),
                identifiers: None,
            },
            now,
        )
        .ok()
        .unwrap()
    }

    #[test]
    fn sealed_login_round_trips_and_is_not_a_usable_raw_state() {
        let reg = register(PASSWORD);
        let start = internal_start_client_login(z(PASSWORD)).ok().unwrap();
        let server = sealed_start(&reg, &start.start_login_request, 1_000);
        let client = client_finish(&start.client_login_state, &server.login_response, PASSWORD);

        let key = internal_finish_server_login_sealed(
            &reg.setup,
            &server.server_login_state,
            &client.finish_login_request,
            1_000,
        )
        .ok()
        .unwrap();
        assert_eq!(*key, *client.session_key);

        // The sealed blob is not a raw state: the legacy path must refuse it.
        assert!(server_finish(&server.server_login_state, &client.finish_login_request).is_err());
    }

    #[test]
    fn sealed_login_rejects_expired_foreign_setup_and_tampered_state() {
        let reg = register(PASSWORD);
        let other = register(PASSWORD);
        let start = internal_start_client_login(z(PASSWORD)).ok().unwrap();
        let server = sealed_start(&reg, &start.start_login_request, 1_000);
        let client = client_finish(&start.client_login_state, &server.login_response, PASSWORD);
        let finish = |setup: &str, state: &str, now: u64| {
            internal_finish_server_login_sealed(setup, state, &client.finish_login_request, now)
        };

        assert!(finish(
            &reg.setup,
            &server.server_login_state,
            1_000 + seal::STATE_TTL_SECS
        )
        .is_ok());
        assert!(finish(
            &reg.setup,
            &server.server_login_state,
            1_000 + seal::STATE_TTL_SECS + 1
        )
        .is_err());
        assert!(finish(&other.setup, &server.server_login_state, 1_000).is_err());

        let mut bytes = BASE64.decode(&*server.server_login_state).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 1;
        assert!(finish(&reg.setup, &BASE64.encode(bytes), 1_000).is_err());
    }
}
