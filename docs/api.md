# API reference

The package namespace is `OPAQUE.Net`.

## `OpaqueClient`

- `StartRegistration(password, out result)` starts client registration.
- `FinishRegistration(password, registrationResponse, clientRegistrationState, out result)` completes registration with default context and KSF settings.
- The extended `FinishRegistration` overload accepts `clientIdentifier`, `serverIdentifier`, and `KSFConfig`.
- `StartLogin(password, out result)` starts client login.
- `FinishLogin(clientLoginState, serverLoginResponse, password, out result)` completes login with default context and KSF settings.
- The extended `FinishLogin` overload accepts `clientIdentifier`, `serverIdentifier`, and `KSFConfig`.

`FinishClientRegistrationResult` contains `RegistrationRecord`, `ExportKey`, and the server static public key. `FinishClientLoginResult` contains `FinishLoginRequest`, `SessionKey`, `ExportKey`, and `ServerStaticPublicKey`.

## `OpaqueServer`

- `CreateSetup(out serverSetup)` creates the server's long-term setup secret.
- `GetPublicKey(serverSetup, out publicKey)` derives the corresponding public key.
- `CreateRegistrationResponse(serverSetup, userIdentifier, registrationRequest, out response)` processes client registration.
- `StartLogin(serverSetup, startLoginRequest, userIdentifier, registrationRecord, out result, out exception)` starts server login and exposes infrastructure failures separately.
- The extended `StartLogin` overload accepts `clientIdentifier` and `serverIdentifier`.
- `FinishLogin(serverLoginState, finishLoginRequest, out serverSessionKey)` completes login.

## Result objects

| Type | Important values |
| --- | --- |
| `StartClientRegistrationResult` | `ClientRegistrationState`, `RegistrationRequest` |
| `FinishClientRegistrationResult` | `RegistrationRecord`, `ExportKey`, `ServerStaicPublicKey` |
| `StartClientLoginResult` | `ClientLoginState`, `StartLoginRequest` |
| `StartServerLoginResult` | `ServerLoginState`, `LoginResponse` |
| `FinishClientLoginResult` | `FinishLoginRequest`, `SessionKey`, `ExportKey`, `ServerStaticPublicKey` |

The state and request properties are flow-specific. Do not reuse them across users, attempts, or concurrent operations.

## `KSFConfig`

`KSFConfig.Create` supports:

- `MemoryConstrained` — the default;
- `RfcDraftRecommended` — the RFC draft recommendation;
- `Custom` — explicit values within the library's validated limits.

`KSFConfig` values are serialized into the native protocol call. Keep registration and login settings consistent.

## Exceptions and return values

`StringParamIsEmptyException` identifies required string arguments that are empty. Native failures are generally represented by `false` and a null output; server login also provides an `Exception` output for infrastructure failures. Applications should normalize these into safe, non-enumerating authentication responses.
