# Security policy

Cyphra OPAQUE.Net is a security-focused fork of [Vaultic-LLC/OPAQUE.Net](https://github.com/Vaultic-LLC/OPAQUE.Net). Our goal is to improve the library and make it safer to use and maintain. Security fixes should be coordinated privately whenever possible.

## Supported versions

The latest published version on the default branch is the primary supported version. Older versions may not receive security fixes; upgrade before reporting a problem as fixed in a newer release.

## Reporting a vulnerability

Do not open a public issue for an unpatched vulnerability. Use the repository's private security advisory feature if enabled, or contact the maintainers privately through the project owner before sharing technical details.

Include:

- affected commit, version, platform, and runtime identifier;
- a concise impact statement;
- reproduction steps or a minimal proof of concept;
- whether exploitation requires local access, a malicious server, a malicious client, or control of the transport;
- any proposed mitigation.

Please do not include real passwords, production secrets, server setup values, registration records, session keys, or personal data.

We will acknowledge receipt, reproduce the report, coordinate a fix and disclosure timeline, and credit the reporter when permission is given.

## Secure use requirements

OPAQUE does not replace TLS, endpoint security, rate limiting, account recovery controls, or secure secret storage. Applications must:

- protect `serverSetup` with a secrets manager and restrict access;
- protect registration records and avoid placing them in logs;
- use authenticated transport and bind the protocol to the intended account/context;
- rate-limit and monitor login attempts;
- treat export keys and session keys as secrets;
- use `StartSealedLogin` / `FinishSealedLogin` for the server side of login. The sealed state is encrypted and authenticated with a key derived from `serverSetup` (XChaCha20-Poly1305, HKDF-SHA512), so it exposes nothing, cannot be forged or altered, is bound to your setup and expires after two minutes; every instance of your service must share the same `serverSetup`. It is not single-use: to reject a replay inside the window, remember the state (or its hash) until it expires. The raw `ServerLoginState` of the obsolete `StartLogin` holds the session key in clear and the key that verifies the client's finish message, so whoever has it can finish the login without the password: never send it to the client or put it in a cookie, URL, log or shared cache;
- avoid revealing whether a user exists or which protocol step failed;
- pin or validate the server public key when the application threat model requires it;
- keep native assets aligned with their runtime identifiers.

## Design notes and known limits

- **Failure reporting.** Protocol failures (wrong password, tampered or malformed message, unknown step) return `false`/`null` without a cause, so callers cannot leak which step failed. Deployment faults are different: a missing or wrong-architecture native library throws `DllNotFoundException`, `EntryPointNotFoundException` or `BadImageFormatException` instead of looking like a failed login.
- **Memory hygiene.** On the native side, passwords, protocol states, keys and `serverSetup` are held in zeroizing buffers, and every string handed to .NET is wiped when freed. .NET strings are immutable and managed, so copies the runtime makes (and the strings returned to your code) cannot be wiped by this library. Keep session and export keys short-lived and do not log them.
- **Panics.** Every native entry point runs inside a panic boundary; an unexpected internal fault yields an empty result rather than terminating the host process.
- **Fixed Argon2 salt.** The key-stretching step uses an all-zero salt. This follows the OPAQUE construction (the password is first blinded through the OPRF, which provides the per-user randomness) and is not a weakness of the Argon2 step.
- **Key-stretching cost.** Argon2id runs only on the client during registration and login finish; the server never runs it. The RFC draft profile allocates about 2 GiB per operation and requires an explicit opt-in (`KSFConfig.CreateRfcDraftRecommended(true)`); custom profiles are capped at 256 MiB, 10 iterations and 16 lanes. Never pick the profile from untrusted input.
- **Dependencies.** CI runs `cargo audit` and fails on known vulnerabilities. GitHub Actions are pinned by commit SHA.

## Security-sensitive changes

Changes to cryptography, protocol state, random number generation, password handling, Argon2id settings, serialization, native interop, memory ownership, or package assets require regression tests and review. See [`CONTRIBUTING.md`](../CONTRIBUTING.md).
