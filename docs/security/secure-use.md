[Docs](../README.md) › Security › **Secure use and known limits**

# Secure use and known limits

To report a vulnerability, see the [security policy](policy.md).

## Secure use requirements

OPAQUE does not replace TLS, endpoint security, rate limiting, account recovery controls, or secure secret storage. Applications must:

- protect `serverSetup` with a secrets manager and restrict access;
- protect registration records and keep them out of logs;
- use authenticated transport and bind the protocol to the intended account and context;
- rate-limit and monitor login attempts, per account and per source. OPAQUE removes offline guessing from a stolen database, but every login attempt is one password guess an online attacker can test, so the server must bound them;
- treat export keys and session keys as secrets;
- use `StartSealedLogin` / `FinishSealedLogin` as described in [sealed login state](#sealed-login-state);
- avoid revealing whether a user exists or which protocol step failed (see [failure handling](../guide/usage.md#failure-handling));
- pin or validate the server public key when the application threat model requires it;
- keep native assets aligned with their runtime identifiers (see [supported platforms](../guide/platforms.md)).

## Sealed login state

The server's login state is sealed before it leaves the native library:

- **Encryption.** XChaCha20-Poly1305 with a key derived from `serverSetup` (HKDF-SHA512). The state exposes nothing and cannot be forged or altered.
- **Binding.** It is bound to your setup and to the user identifier it was started for: `FinishSealedLogin` takes the identifier and fails for any other.
- **Expiry.** Two minutes. Every instance of your service must share the same `serverSetup` and keep its clock synchronized (NTP), because the expiry is checked against the local clock. A state whose expiry lies more than 2 minutes + 30 s ahead (a clock that ran ahead or stepped back) is refused.
- **Single use.** `FinishSealedLogin` requires `tryConsume` (shared atomic storage across instances, or one process-wide [`LoginStateReplayCache`](../reference/api.md#loginstatereplaycache) for a single instance) to reject a replay inside the window.
- **Why it is sealed.** The unsealed server state holds the session key in clear and the key that verifies the client's finish message, so whoever had it could finish the login without the password. It never crosses the native boundary.

## Design notes and known limits

- **Failure reporting.** Protocol failures (wrong password, tampered or malformed message, unknown step) return `false`/`null` without a cause, so callers cannot leak which step failed. Deployment faults are different: a missing or wrong-architecture native library throws `DllNotFoundException`, `EntryPointNotFoundException` or `BadImageFormatException` instead of looking like a failed login.
- **Account-existence timing.** For an unknown user the server answers `StartSealedLogin` with a dummy response instead of failing, and a record that cannot be decoded takes the same path, so the reply does not say whether the account exists. The two paths are not constant-time: in-process the real-record path differs from the absent-record path by about 1% (around 10 µs), far below network jitter but measurable with many local samples. Padding the absent-record path with a dummy record parse overshoots by about as much in the other direction (opaque-ke's own dummy path is the slower half), so it is not done. Where account enumeration matters, rate-limit login starts per client and per account.
- **Memory hygiene.** On the native side, passwords, protocol states, keys, `serverSetup` and the Argon2 memory matrix are held in zeroizing buffers, and every string handed to .NET is wiped when freed. Passwords and `serverSetup` cross into native code through pinned buffers that are zeroed after the call, not through the runtime's string marshalling. .NET strings are immutable and managed, so copies the runtime makes (and the strings returned to your code) cannot be wiped by this library. Keep session and export keys short-lived and do not log them.
- **Panics.** Every native entry point runs inside a panic boundary; an unexpected internal fault yields an empty result rather than terminating the host process.
- **Fixed Argon2 salt.** The key-stretching step uses an all-zero salt. This follows the OPAQUE construction (the password is first blinded through the OPRF, which provides the per-user randomness) and is not a weakness of the Argon2 step.
- **Key-stretching cost.** Argon2id runs only on the client during registration and login finish; the server never runs it. The RFC draft profile allocates about 2 GiB per operation and requires an explicit opt-in (`KSFConfig.CreateRfcDraftRecommended(true)`); custom profiles are capped at 256 MiB, 10 iterations and 16 lanes. Never pick the profile from untrusted input.
- **Native library loading.** `NativeLibraryResolver` loads the library only from directories resolved by the .NET host and never falls back to the operating-system search of a bare name, so a library planted through `LD_LIBRARY_PATH`, `PATH` or the working directory is not picked up. Failures throw `DllNotFoundException` with the probed directories. If another resolver was registered for the assembly first, it takes over and a trace warning is written. Keep the application directory itself unwritable by untrusted users. The Windows builds link the C runtime statically, so `opaque.dll` imports only system DLLs and its own dependencies are not searched for in the working directory or `PATH`.
- **Dependencies.** CI runs `cargo audit` (failing on known-vulnerable, unsound or yanked crates) and `cargo deny check` (advisories, licenses, sources and wildcard bans from `deny.toml`). GitHub Actions are pinned by commit SHA, and Zig and `cargo-zigbuild` are installed from hash-pinned wheels.
- **Known advisory: RUSTSEC-2026-0387 (`crypto-bigint` 0.5.5, timing variability).** Ignored in `.cargo/audit.toml` because no usable fix exists: it is pulled in only through `elliptic-curve` 0.13, which `opaque-ke` pins, and the patched `crypto-bigint` needs `elliptic-curve` 0.14. The default Ristretto255 build does no arithmetic through it; the optional `p256` Cargo feature does, so avoid that feature on hosts where an attacker can time operations until `opaque-ke` is updated. The ignore is removed once it is.

---

**Previous:** [API reference](../reference/api.md) · **See also:** [Security policy](policy.md), [Architecture](../development/architecture.md)
