# Cyphra OPAQUE.Net documentation

Cyphra OPAQUE.Net is a .NET 8 wrapper around a Rust implementation of the OPAQUE password-authenticated key-exchange protocol.

This documentation describes the current fork, its API, native boundary, supported platforms, and contribution practices. The project was forked from [Vaultic-LLC/OPAQUE.Net](https://github.com/Vaultic-LLC/OPAQUE.Net) to receive ongoing maintenance and security improvements.

## Contents

- [Usage and protocol flow](usage.md) — registration, login, identifiers, keys, and failure handling;
- [API reference](api.md) — public classes, result objects, and `KSFConfig`;
- [Architecture](architecture.md) — managed code, Rust, FFI, and native asset loading;
- [Building and testing](building.md) — local builds, supported runtime identifiers, and packaging;
- [Security policy](security.md) — vulnerability reporting and secure-use requirements.

## Important terms

| Term | Meaning |
| --- | --- |
| `serverSetup` | The server's long-term OPAQUE setup secret. Store it as a secret; changing it invalidates existing registration records. |
| Registration record | The verifier/credential record returned to the server after client registration. It is not the user's plaintext password. |
| Export key | A stable key available to the client after registration or login, not to the server. |
| Session key | A key derived by both client and server during a successful login. |
| Native library | The Rust `cdylib` loaded by the .NET wrapper through C ABI functions. |

## Security model

OPAQUE is designed so that the server does not receive the user's password during registration or login. It does not make weak passwords safe, remove the need for TLS, or protect an application from endpoint compromise. Applications must still protect transport, account identifiers, server secrets, stored records, and derived keys.

Do not log or persist passwords, transient protocol state, session keys, or `serverSetup` in ordinary application logs. See [Security policy](security.md) before deploying the library.
