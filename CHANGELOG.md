# Changelog

## Unreleased

- **Sealed server login state (#13, F-01).** New `OpaqueServer.StartSealedLogin` / `FinishSealedLogin` and `StartSealedServerLoginResult`. The server state is encrypted and authenticated (XChaCha20-Poly1305, key derived from `serverSetup` with HKDF-SHA512) and expires after 120 s, so it can no longer be used to forge the client's finish message or read the session key. It stays stateless: any instance sharing the setup can finish a login. It is not single-use; remember the state until it expires to reject replays.
- `OpaqueServer.StartLogin` and `FinishLogin(serverLoginState, …)` are `[Obsolete]`: the raw state they produce is a bearer secret. They keep working and will be removed in 2.0. Migration: replace the pair with `StartSealedLogin` / `FinishSealedLogin(serverSetup, …)`; sealed and raw states are not interchangeable, so finish in-flight logins with the API that started them.
- New native dependencies: `chacha20poly1305` (and its RustCrypto dependencies).

## 1.5.0

Stricter input validation. Inputs that were previously accepted or failed silently now throw before the native call:

- Passwords and identifiers containing `\0` or an unpaired surrogate throw `ArgumentException` (previously truncated or replaced with U+FFFD, so different inputs could collide).
- The 1024 limit for passwords and identifiers is measured in UTF-8 bytes; exceeding it throws `ArgumentOutOfRangeException` (previously a silent `false` for non-ASCII text). No Unicode normalization is applied: NFC and NFD are different passwords.
- `KSFConfig.Create(KSFConfigType.RfcDraftRecommended)` throws; use `CreateRfcDraftRecommended(true)`. Undefined enum values throw.
- `OpaqueServer.CreateRegistrationResponse` rejects registration requests with trailing bytes.
