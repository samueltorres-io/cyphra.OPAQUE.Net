# Changelog

## Unreleased

No change to the library's behavior or public API.

### Dependencies

- Linux builds use Zig 0.17.1 and `cargo-zigbuild` 0.24.1 (from 0.13.0 and 0.20.1); the glibc 2.17 floor is unchanged.
- Test project: MSTest 4.5.2 (from 3.1.1), Microsoft.NET.Test.Sdk 18.11.0 (from 17.8.0), coverlet.collector 10.1.0 (from 6.0.0). The tests use `Assert.ThrowsExactly`, since MSTest 4 removed `Assert.ThrowsException`.

### Tests

- Every result type that holds secrets is checked for a redacted `ToString()`, not only `StartSealedServerLoginResult`.

### Docs

- `docs/` is reorganized by audience: `guide/`, `reference/`, `security/` and `development/`, with new pages for supported platforms, the security policy and releases. Content is synced with 2.0: result handles are tokens, `KSFConfig` crosses the FFI as numbers, and `StartSealedLogin` accepts a null record for unknown users.
- Code comments are removed from the C# and Rust sources. The public XML docs (IntelliSense) stay, and the design rationale moved to `docs/`.

## 2.0.0

Security and cleanup release from a full audit. **Breaking**: read "Migrating from 1.x" first.

### Breaking changes

- **Sealed login states are bound to the user identifier.** `StartSealedLogin` authenticates `userIdentifier` together with the sealed state (seal format version 2; version 1 states in flight at upgrade fail once). Finish with `FinishSealedLogin(serverSetup, userIdentifier, sealedLoginState, finishLoginRequest, tryConsume, out serverSessionKey)`, which fails for any other user and is always single-use. Before, a valid state and finish message of one account could complete a login presented for another account, and the overload without `tryConsume` was replayable for two minutes. The two overloads without `userIdentifier` are `[Obsolete(error: true)]` and throw `NotSupportedException`. The native `finish_server_login_sealed` export takes the identifier as its second argument.
- **Raw server login API removed.** `OpaqueServer.StartLogin` (both overloads), `OpaqueServer.FinishLogin`, `StartServerLoginResult` and the native `start_server_login` / `finish_server_login` exports are gone: the raw state was a bearer secret.
- **`KSFConfig` is numeric.** `Iterations`, `Memory` and `Parallelism` are `int?` (set only for the custom profile) and `TypeString` is removed; the FFI passes the profile and costs as numbers. `KSFConfigType` values are explicit (0-2).
- **Removed compatibility members:** `StringParamIsEmptyException.MaximumPasswordLength` / `MaximumIdentifierLength` / `MaximumProtocolMessageLength`, `ThrowIfEmpty`, `ThrowIfLongerThan`; `FinishClientRegistrationResult.ServerStaicPublicKey`; `FunctionHelper` is internal.
- `StringParamIsEmptyException` derives from `ArgumentException`, so one `catch (ArgumentException)` covers every argument check.

### Security fixes

- An undecodable stored registration record (corrupt, placeholder, other cipher suite, trailing bytes) takes the unknown-user dummy path instead of failing fast, which was an account-existence oracle.
- Sealed states whose expiry is more than TTL + 30 s ahead are refused.
- Native result handles are never-reused tokens instead of addresses, so a stale handle can no longer reach a newer result allocated at the same address.
- Passwords and `serverSetup` cross the FFI through pinned buffers that are zeroed after the call; the Argon2 memory matrix and serialized secret temporaries are zeroized (about 25% more client login latency).
- Result types holding secrets have redacted `ToString()` and `[JsonIgnore]` where applicable.
- `TryExecute` rethrows process-level faults (out of memory, stack, marshalling, SEH) instead of reporting them as a failed login; native results are read inside it.
- `NativeLibraryResolver` ignores relative probe directories and traces when another resolver pre-empts it. Windows builds link the C runtime statically, so `opaque.dll` imports only system DLLs.
- Release profile enables `overflow-checks`.

### CI and supply chain

- The release gate uses `refs/remotes/origin/main` (a tag named `origin/main` could shadow it); the main-source check requires the PR to come from this repository; the release tag reaches pwsh through an environment variable; release assets are no longer `--clobber`ed, so GitHub and NuGet cannot diverge on a re-run.
- `persist-credentials: false` on every checkout; the native artifact is uploaded before any restore or test code runs.
- `cargo audit` denies unsound and yanked crates, and `cargo deny check` enforces `deny.toml`. Dependabot covers the zig wheels and both NuGet projects, with a cooldown. `pack-and-verify.sh` rejects unexpected package entries and checks native architectures.

### Cleanup

- Native core: payload-free unit `Error`, `unwrap_or_default` at the entry points, one 64 KiB limit constant, no duplicated null checks, sealed start decodes the setup once.
- .NET: one `ParamGuard` call per argument, no redundant handle checks or empty constructors.
- Docs: private vulnerability reporting through GitHub, `usage.md` uses one process-wide `LoginStateReplayCache`, the account-existence timing residual (~1%) and clock dependence are documented.

### Migrating from 1.x

1. Replace `StartLogin` / `FinishLogin(serverLoginState, …)` with `StartSealedLogin` / `FinishSealedLogin`.
2. Pass the same `userIdentifier` to `FinishSealedLogin` that you passed to `StartSealedLogin`, plus a `tryConsume` backed by shared atomic storage (or one process-wide `LoginStateReplayCache` for a single instance).
3. Read `KSFConfig.Iterations` / `Memory` / `Parallelism` as `int?`; drop uses of `TypeString`.
4. Replace `StringParamIsEmptyException.Maximum*` with your own constants and `ServerStaicPublicKey` with `ServerStaticPublicKey`.
5. Logins in flight during the upgrade fail once (seal format v2); the client simply retries.

## 1.6.0

- **Native dependencies bumped:** `argon2` 0.6, `hkdf` 0.13 (with `sha2` 0.11, which it requires), `chacha20poly1305` 0.11, `base64` 0.23, `libc`, `zeroize`, plus a full `Cargo.lock` refresh. Argon2id, HKDF-SHA512 and XChaCha20-Poly1305 outputs are byte-identical to the previous versions (checked with fixed vectors), so existing registrations and sealed states stay valid. `generic-array` stays on 0.14: opaque-ke 3.0's `Ksf` trait is defined over it, and 0.14.9 deprecates its API, so the use is scoped with `#[allow(deprecated)]`.
- The `opaque-ke` `argon2` feature is no longer enabled (the library uses its own Argon2 key stretching), which removes `argon2` 0.5, `blake2` 0.10 and `password-hash` 0.5 from the build.
- New `deny.toml` for `cargo deny check` (licenses, bans, sources, advisories).
- **BREAKING: `RfcDraftRecommended` memory is now exactly 2^21 KiB** (it was 2^21 - 1, which Argon2 rounds down), matching draft-irtf-cfrg-opaque-16. Records created with this profile no longer authenticate and must be re-registered; `MemoryConstrained` and `Custom` are unchanged.
- **Sealed server login state (#13, F-01).** New `OpaqueServer.StartSealedLogin` / `FinishSealedLogin` and `StartSealedServerLoginResult`. The server state is encrypted and authenticated (XChaCha20-Poly1305, key derived from `serverSetup` with HKDF-SHA512) and expires after 120 s, so it can no longer be used to forge the client's finish message or read the session key. It stays stateless: any instance sharing the setup can finish a login. New overload `FinishSealedLogin(…, Func<string, bool> tryConsume, …)` and `LoginStateReplayCache` enforce single use (#14, F-02): the state id is consumed only after the login verifies, and a second use fails. Multi-instance deployments must back `tryConsume` with shared storage.
- `OpaqueServer.StartLogin` and `FinishLogin(serverLoginState, …)` are `[Obsolete]`: the raw state they produce is a bearer secret. They keep working and will be removed in 2.0. Migration: replace the pair with `StartSealedLogin` / `FinishSealedLogin(serverSetup, …)`; sealed and raw states are not interchangeable, so finish in-flight logins with the API that started them.
- **Strict native library loading (F-09, F-10).** The library is loaded only from directories resolved by the .NET host; the OS search of a bare name is no longer a fallback. Load failures throw `DllNotFoundException` naming the runtime identifier and the probed (or found-but-unloadable) paths. Applications that relied on `LD_LIBRARY_PATH`/`PATH` to supply the native library must deploy it with the app (the NuGet `runtimes/<rid>/native` layout already does).
- Building for an unsupported runtime identifier (musl, `win-x86`, `linux-arm`, mobile, browser) now warns with `OPAQUE001`. `FunctionHelper` is hidden from IntelliSense and becomes internal in 2.0.
- **Unsupported runtime identifiers (#17).** `docs/building.md` now lists them, the run-time failure mode, how to turn `OPAQUE001` into an error, and the Alpine workaround (glibc base image).
- **Review fixes.** The sealed-state clock now fails closed when the system clock is before 1970 (it used to read as 0 and disable expiry). `LoginStateReplayCache` retains ids on the wall clock, the same clock that expires states. `OPAQUE001` also covers `freebsd`, `illumos`, `solaris`, `haiku` and `maccatalyst`. `cargo audit` runs in its own CI job, apart from the jobs whose output is packed. `docs/usage.md` shows the single-use `FinishSealedLogin` overload.
- **Packaging (F-11).** Source Link and embedded symbols, deterministic assembly in CI; `opaque-ke` requirement tightened to 3.0.0; tests also run on .NET 10; README documents provenance verification.
- **CI (F-07).** Zig installed with pinned hashes, no network rustup installer, no restored cache in release builds. cargo-zigbuild now comes from a hash-pinned wheel too (#15).
- **Advisory RUSTSEC-2026-0387** (`crypto-bigint` timing) is explicitly ignored in `cargo audit`; not fixable until `opaque-ke` supports `elliptic-curve` 0.14. Affects only the optional `p256` feature. See `docs/security.md`.
- **Security review (1.6.0).** `cargo audit` is clean apart from the documented RUSTSEC-2026-0387; no `unwrap`/`expect`/`panic!` in non-test native code. Hardening: the assembly sets `DefaultDllImportSearchPaths(AssemblyDirectory)` (CA5392) so that, should the strict resolver ever not run, the runtime's own probing is still limited to the assembly directory; the intermediate byte buffer behind every native string (session/export keys) is wiped; the Argon2 input (the OPRF output) is wiped after hashing and `argon2`'s `zeroize` feature is on (no new crate); Dependabot keeps the SHA-pinned actions, cargo and NuGet dependencies current. The Argon2 state matrix is deliberately not wiped (it costs ~25% of the login latency and is returned to the OS on free).
- **Performance.** The native library is built with `opt-level = 2` instead of `"s"`: the Argon2id step of a `MemoryConstrained` login is about 27% faster (213 ms vs 292 ms measured) for a 1.7% larger library.
- **Native handle registries (hardening).** The result-handle registry is keyed by address and type, so a stale pointer whose address was reused by another result type can no longer free it as the wrong type, and a panic while a registry lock is held no longer poisons it (it used to make every later native call return null for the rest of the process).
- **Docs.** The README install command named the upstream `Vaultic.OPAQUE.Net` package instead of `Cyphra.OPAQUE.Net`; `docs/api.md` and `docs/usage.md` no longer present the obsolete `ServerStaicPublicKey` spelling as current.
- **Tests.** Added coverage for sealed login with client/server identifiers, `LoginStateReplayCache` under contention, `KSFConfig` bounds, named KSF profiles, identifier parsing and wrong-type handle release.
- **Package hygiene (#18).** The library now multi-targets `net8.0` and `net10.0` (.NET 8 support ends 2026-11-10); the release workflow installs both SDKs and asserts both `lib/` assemblies are in the package. CI already runs the tests on both. Two `dotnet pack` runs of the same commit with `ContinuousIntegrationBuild` (set automatically in GitHub Actions) yield byte-identical entries, assemblies included; only the zip entry timestamps of the generated nuspec/`.rels` differ, so the `.nupkg` hash itself is not reproducible. Compare the assemblies, or the build provenance attestation (`gh attestation verify`), instead. `opaque-ke` stays on 3.0.0: the only newer release is the pre-release 4.1.0-pre.2.

## 1.5.0

Stricter input validation. Inputs that were previously accepted or failed silently now throw before the native call:

- Passwords and identifiers containing `\0` or an unpaired surrogate throw `ArgumentException` (previously truncated or replaced with U+FFFD, so different inputs could collide).
- The 1024 limit for passwords and identifiers is measured in UTF-8 bytes; exceeding it throws `ArgumentOutOfRangeException` (previously a silent `false` for non-ASCII text). No Unicode normalization is applied: NFC and NFD are different passwords.
- `KSFConfig.Create(KSFConfigType.RfcDraftRecommended)` throws; use `CreateRfcDraftRecommended(true)`. Undefined enum values throw.
- `OpaqueServer.CreateRegistrationResponse` rejects registration requests with trailing bytes.
