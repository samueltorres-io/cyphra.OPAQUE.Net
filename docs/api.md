# API reference

The package namespace is `OPAQUE.Net`.

Every string argument, including protocol messages received from the other party, is checked before the native call: an empty value throws `StringParamIsEmptyException`, an embedded NUL or unpaired surrogate throws `ArgumentException`, and an oversized value throws `ArgumentOutOfRangeException`. All three are `ArgumentException`s. The methods return `false` only once the input reaches the protocol, so when you pass remote input, catch `ArgumentException` and treat it as a failed attempt.

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
- `StartSealedLogin(serverSetup, startLoginRequest, userIdentifier, registrationRecord, out result, out exception)` starts server login, returns the server state sealed under the setup. Its `exception` is set only when the managed call into the native library throws; native failures (an undecodable setup, a clock before 1970, a sealing error) return `false` with `exception` null, like a protocol failure, so validate `serverSetup` once at startup with `GetPublicKey`. The extended overload accepts `clientIdentifier` and `serverIdentifier`.
- `FinishSealedLogin(serverSetup, userIdentifier, sealedLoginState, finishLoginRequest, tryConsume, out serverSessionKey)` completes login once. It fails for a state that was altered, expired (2 minutes), sealed under another setup, or started for another `userIdentifier`, so a success authenticates exactly that user. The overloads without `userIdentifier` are obsolete (compile error) and throw `NotSupportedException`.
- `StartLogin` / `FinishLogin(serverLoginState, …)` are obsolete: the raw state they use is a bearer secret (see [security](security.md)).

## `LoginStateReplayCache`

`TryConsume(id)` returns true the first time an id is seen and false afterwards, for 5 minutes (longer than a sealed state lives). It is thread-safe and in-memory, so it is correct only for a single server instance and forgets everything on restart; use shared storage with an atomic set-if-absent for several instances or restarts. Pass `TryConsume` as the `tryConsume` argument of `FinishSealedLogin`.

## Result objects

| Type | Important values |
| --- | --- |
| `StartClientRegistrationResult` | `ClientRegistrationState`, `RegistrationRequest` |
| `FinishClientRegistrationResult` | `RegistrationRecord`, `ExportKey`, `ServerStaticPublicKey` |
| `StartClientLoginResult` | `ClientLoginState`, `StartLoginRequest` |
| `StartSealedServerLoginResult` | `SealedLoginState`, `LoginResponse` |
| `StartServerLoginResult` (obsolete) | `ServerLoginState`, `LoginResponse` |
| `FinishClientLoginResult` | `FinishLoginRequest`, `SessionKey`, `ExportKey`, `ServerStaticPublicKey` |

The result types override `ToString()` to print only their type name, but their properties are plain strings: never serialize a result object, log it field by field, or keep it longer than the step that needs it. Send only `LoginResponse` to the client. `SealedLoginState` is valid for two minutes but not single-use by itself: `FinishSealedLogin(serverSetup, userIdentifier, sealedLoginState, finishLoginRequest, tryConsume, out serverSessionKey)` refuses a second use. `tryConsume` receives a stable id of the state and must atomically record it and return true only the first time (shared storage such as Redis `SET NX` with a TTL of at least 120 s for several instances; `LoginStateReplayCache.TryConsume` for a single instance). It runs only after the state and the finish message verify, so a bad finish does not burn the state. The raw `ServerLoginState` of the obsolete API is a server-side secret (see [security](security.md)). The state and request properties are flow-specific. Do not reuse them across users, attempts, or concurrent operations.

## `KSFConfig`

`KSFConfig.Create` supports:

- `MemoryConstrained` — the default;
- `RfcDraftRecommended` — the RFC draft recommendation (about 2 GiB); `KSFConfig.Create` throws for it, use `CreateRfcDraftRecommended(true)`;
- `Custom` — explicit values within the library's validated limits.

`KSFConfig` values are serialized into the native protocol call. Keep registration and login settings consistent.

## Exceptions and return values

`StringParamIsEmptyException` identifies required string arguments that are empty. Passwords and identifiers are validated before the native call: embedded `\0` and unpaired surrogates throw `ArgumentException`, and the 1024 limit is measured in UTF-8 bytes (`ArgumentOutOfRangeException`). No Unicode normalization is applied, so NFC and NFD forms of the same text are different passwords; normalize in the application if needed. Native failures are generally represented by `false` and a null output; server login also provides an `Exception` output for infrastructure failures. Applications should normalize these into safe, non-enumerating authentication responses.
