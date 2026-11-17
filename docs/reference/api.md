[Docs](../README.md) › Reference › **API reference**

# API reference

| Namespace | Contents |
| --- | --- |
| `OPAQUE.Net` | [`OpaqueClient`](#opaqueclient), [`OpaqueServer`](#opaqueserver), [`LoginStateReplayCache`](#loginstatereplaycache) |
| `OPAQUE.Net.Types.Results` | [Result objects](#result-objects) |
| `OPAQUE.Net.Types.Parameters` | [`KSFConfig`, `KSFConfigType`](#ksfconfig) |
| `OPAQUE.Net.Types.Exceptions` | [`StringParamIsEmptyException`](#exceptions-and-return-values) |

For the order in which these are called, see [Usage and protocol flow](../guide/usage.md).

**Argument checks.** Every string argument, including protocol messages received from the other party, is checked before the native call. An empty required value throws `StringParamIsEmptyException`, an embedded NUL or unpaired surrogate throws `ArgumentException`, and an oversized value throws `ArgumentOutOfRangeException`. All three are `ArgumentException`s. The methods return `false` only once the input reaches the protocol, so when you pass remote input, catch `ArgumentException` and treat it as a failed attempt.

## `OpaqueClient`

| Method | Purpose |
| --- | --- |
| `StartRegistration(password, out result)` | Starts client registration. |
| `FinishRegistration(password, registrationResponse, clientRegistrationState, out result)` | Completes registration with default context and the `MemoryConstrained` KSF profile. |
| `FinishRegistration(password, registrationResponse, clientRegistrationState, clientIdentifier, serverIdentifier, config, out result)` | Same, with optional identifiers and `KSFConfig` (`null` = default). |
| `StartLogin(password, out result)` | Starts client login. |
| `FinishLogin(clientLoginState, serverLoginResponse, password, out result)` | Completes login with default context and the `MemoryConstrained` KSF profile. |
| `FinishLogin(clientLoginState, serverLoginResponse, password, clientIdentifier, serverIdentifier, config, out result)` | Same, with optional identifiers and `KSFConfig` (`null` = default). |

Identifiers and `KSFConfig` must be identical at registration and login, or login fails.

## `OpaqueServer`

| Method | Purpose |
| --- | --- |
| `CreateSetup(out serverSetup)` | Creates the server's long-term setup secret. |
| `GetPublicKey(serverSetup, out publicKey)` | Derives the public key. Also the way to validate a stored setup at startup. |
| `CreateRegistrationResponse(serverSetup, userIdentifier, registrationRequest, out response)` | Processes client registration. |
| `StartSealedLogin(serverSetup, startLoginRequest, userIdentifier, registrationRecord, out result, out exception)` | Starts server login and returns the server state sealed under the setup. The extended overload adds `clientIdentifier` and `serverIdentifier`. |
| `FinishSealedLogin(serverSetup, userIdentifier, sealedLoginState, finishLoginRequest, tryConsume, out serverSessionKey)` | Completes login, once. |

**`StartSealedLogin`**

- `registrationRecord` is the user's record, or `null`/empty when the user does not exist. An absent or undecodable record still gets an ordinary response, and the login fails at the finish step, so the reply does not reveal whether the account exists.
- `exception` is set only when the managed call into the native library throws. Native failures (an undecodable setup, a clock before 1970, a sealing error) return `false` with `exception` null, like a protocol failure, so validate `serverSetup` once at startup with `GetPublicKey`.

**`FinishSealedLogin`**

- Fails for a state that was altered, expired (2 minutes), sealed under another setup, or started for another `userIdentifier`, so a success authenticates exactly that user.
- `tryConsume` receives a stable id of the state (SHA-256 hex of the sealed value) and must atomically record it and return `true` only the first time. Use shared storage such as Redis `SET NX` with a TTL of at least 120 s for several instances, or [`LoginStateReplayCache.TryConsume`](#loginstatereplaycache) for a single instance. It runs only after the state and the finish message verify, so a bad finish message does not burn the state.
- The native base64url decoding is canonical (no padding, no spare bits), so each sealed state has exactly one string form and re-encoding it cannot produce a fresh id.
- If `tryConsume` returns `false` or throws, no session key is returned (`serverSessionKey` is null); an exception propagates to the caller.
- The overloads without `userIdentifier` are `[Obsolete(error: true)]` (compile error) and throw `NotSupportedException`.

## `LoginStateReplayCache`

`TryConsume(id)` returns `true` the first time an id is seen and `false` afterwards, for 5 minutes (longer than a sealed state lives, to cover clock skew). It is thread-safe and in-memory, so it is correct only for a single server instance and forgets everything on restart.

Retention follows the wall clock on purpose, the same clock the native library uses to expire states: a backward clock step keeps ids longer instead of dropping them while a state is still valid. Expired ids are swept at most once a minute, so `TryConsume` stays O(1) amortized. Create one per process (a static field or a DI singleton). For several instances or restarts, use shared storage with an atomic set-if-absent. Pass `TryConsume` as the `tryConsume` argument of `FinishSealedLogin`.

## Result objects

| Type | Returned by | Values |
| --- | --- | --- |
| `StartClientRegistrationResult` | `OpaqueClient.StartRegistration` | `ClientRegistrationState`, `RegistrationRequest` |
| `FinishClientRegistrationResult` | `OpaqueClient.FinishRegistration` | `RegistrationRecord`, `ExportKey`, `ServerStaticPublicKey` |
| `StartClientLoginResult` | `OpaqueClient.StartLogin` | `ClientLoginState`, `StartLoginRequest` |
| `StartSealedServerLoginResult` | `OpaqueServer.StartSealedLogin` | `SealedLoginState`, `LoginResponse` |
| `FinishClientLoginResult` | `OpaqueClient.FinishLogin` | `FinishLoginRequest`, `SessionKey`, `ExportKey`, `ServerStaticPublicKey` |

- **Redacted `ToString()`.** The result types print only their type name, but their properties are plain strings: never serialize a result object, log it field by field, or keep it longer than the step that needs it.
- **What goes over the wire.** Requests and responses go to the other party. Of `StartSealedServerLoginResult`, send only `LoginResponse`; `SealedLoginState` stays on the server.
- **One flow, one set of values.** State and request properties belong to one flow. Do not reuse them across users, attempts or concurrent operations.

## `KSFConfig`

Selects the Argon2id key-stretching profile. It is part of the credential format: keep registration and login settings identical.

| Member | Description |
| --- | --- |
| `KSFConfig.Create(type, iterations, memory, parallelism)` | `MemoryConstrained` (the default) or `Custom`. `Custom` requires all three values within the limits below. Throws for `RfcDraftRecommended`. |
| `KSFConfig.CreateRfcDraftRecommended(allowHighMemoryProfile)` | The RFC draft profile (about 2 GiB per operation). Throws unless `allowHighMemoryProfile` is `true`. |
| `Type` | The `KSFConfigType`. |
| `Iterations`, `Memory`, `Parallelism` | `int?`, set only for `Custom`. `Memory` is in KiB. |
| `MinimumIterations` / `MaximumIterations` | 1 / 10 |
| `MinimumMemoryKiB` / `MaximumCustomMemoryKiB` | 65536 (64 MiB) / 262144 (256 MiB) |
| `MinimumParallelism` / `MaximumParallelism` | 1 / 16 |

`KSFConfigType` values are explicit because they cross the native boundary: `RfcDraftRecommended = 0`, `MemoryConstrained = 1`, `Custom = 2`. The profile and costs are passed to the native call as numbers.

## Exceptions and return values

- **`StringParamIsEmptyException`** (derives from `ArgumentException`) identifies required string arguments that are empty.
- **Limits.** Passwords and identifiers: at most 1024 UTF-8 bytes, no embedded `\0`, no unpaired surrogates. Protocol messages: at most 64 KiB.
- **No Unicode normalization.** NFC and NFD forms of the same text are different passwords; normalize in the application if needed.
- **Native failures** are represented by `false` and a null output; `StartSealedLogin` also has an `Exception` output for infrastructure failures.

Normalize all of these into safe, non-enumerating authentication responses; the full table is in [failure handling](../guide/usage.md#failure-handling).

---

**Previous:** [Supported platforms](../guide/platforms.md) · **Next:** [Secure use and known limits](../security/secure-use.md)
