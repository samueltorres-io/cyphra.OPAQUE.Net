# Changelog

## Unreleased

- **Sealed server login state (#13, F-01).** New `OpaqueServer.StartSealedLogin` / `FinishSealedLogin` and `StartSealedServerLoginResult`. The server state is encrypted and authenticated (XChaCha20-Poly1305, key derived from `serverSetup` with HKDF-SHA512) and expires after 120 s, so it can no longer be used to forge the client's finish message or read the session key. It stays stateless: any instance sharing the setup can finish a login. New overload `FinishSealedLogin(…, Func<string, bool> tryConsume, …)` and `LoginStateReplayCache` enforce single use (#14, F-02): the state id is consumed only after the login verifies, and a second use fails. Multi-instance deployments must back `tryConsume` with shared storage.
- `OpaqueServer.StartLogin` and `FinishLogin(serverLoginState, …)` are `[Obsolete]`: the raw state they produce is a bearer secret. They keep working and will be removed in 2.0. Migration: replace the pair with `StartSealedLogin` / `FinishSealedLogin(serverSetup, …)`; sealed and raw states are not interchangeable, so finish in-flight logins with the API that started them.
- New native dependencies: `chacha20poly1305` (and its RustCrypto dependencies).
- **Strict native library loading (F-09, F-10).** The library is loaded only from directories resolved by the .NET host; the OS search of a bare name is no longer a fallback. Load failures throw `DllNotFoundException` naming the runtime identifier and the probed (or found-but-unloadable) paths. Applications that relied on `LD_LIBRARY_PATH`/`PATH` to supply the native library must deploy it with the app (the NuGet `runtimes/<rid>/native` layout already does).
- Building for an unsupported runtime identifier (musl, `win-x86`, `linux-arm`, mobile, browser) now warns with `OPAQUE001`. `FunctionHelper` is hidden from IntelliSense and becomes internal in 2.0.
- **Packaging (F-11).** Source Link and embedded symbols, deterministic assembly in CI; `opaque-ke` requirement tightened to 3.0.0; tests also run on .NET 10; README documents provenance verification.
- **CI (F-07).** Zig installed with pinned hashes, no network rustup installer, no restored cache in release builds.

## 1.5.0

Stricter input validation. Inputs that were previously accepted or failed silently now throw before the native call:

- Passwords and identifiers containing `\0` or an unpaired surrogate throw `ArgumentException` (previously truncated or replaced with U+FFFD, so different inputs could collide).
- The 1024 limit for passwords and identifiers is measured in UTF-8 bytes; exceeding it throws `ArgumentOutOfRangeException` (previously a silent `false` for non-ASCII text). No Unicode normalization is applied: NFC and NFD are different passwords.
- `KSFConfig.Create(KSFConfigType.RfcDraftRecommended)` throws; use `CreateRfcDraftRecommended(true)`. Undefined enum values throw.
- `OpaqueServer.CreateRegistrationResponse` rejects registration requests with trailing bytes.
