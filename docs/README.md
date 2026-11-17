# Cyphra OPAQUE.Net documentation

Cyphra OPAQUE.Net is a .NET wrapper (`net8.0` and `net10.0`) around a Rust implementation of the [OPAQUE](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/) password-authenticated key-exchange protocol: the server authenticates a user without ever receiving the password, and both sides derive a session key.

The project is a security-focused fork of [Vaultic-LLC/OPAQUE.Net](https://github.com/Vaultic-LLC/OPAQUE.Net). Upgrading from 1.x? Read the [migration guide in the changelog](../CHANGELOG.md#migrating-from-1x) first.

Também disponível em [português](README.pt-BR.md) (índice).

## Where to start

| I want to… | Read |
| --- | --- |
| Add OPAQUE login to my application | [Usage and protocol flow](guide/usage.md), then [API reference](reference/api.md) |
| Know which platforms and runtimes are supported | [Supported platforms](guide/platforms.md) |
| Deploy it safely | [Secure use and known limits](security/secure-use.md) |
| Report a vulnerability | [Security policy](security/policy.md) |
| Understand how .NET and Rust fit together | [Architecture](development/architecture.md) |
| Build, test or add a platform | [Building and testing](development/building.md) |
| Cut a release | [Packaging and releases](development/releasing.md) |

## Map

```text
docs/
├── guide/                 using the library
│   ├── usage.md           server setup, registration, login, Argon2id, failure handling
│   └── platforms.md       supported RIDs, unsupported targets, native loading, release verification
├── reference/
│   └── api.md             public classes, result objects, KSFConfig, exceptions
├── security/
│   ├── policy.md          supported versions, private reporting, security-sensitive changes
│   └── secure-use.md      deployment requirements, design notes and known limits
└── development/           contributing to the library
    ├── architecture.md    layers, native boundary, state, ABI evolution
    ├── building.md        prerequisites, native builds, tests, adding a platform
    └── releasing.md       packaging rules, release checklist, publish workflow
```

Outside `docs/`: [CONTRIBUTING.md](../CONTRIBUTING.md) (workflow and pull requests) and [CHANGELOG.md](../CHANGELOG.md) (release history and migrations).

## Important terms

| Term | Meaning |
| --- | --- |
| `serverSetup` | The server's long-term OPAQUE setup secret. Store it as a secret; changing it invalidates existing registration records. See [server setup](guide/usage.md#server-setup). |
| Registration record | The verifier/credential record the server stores after registration. It is not the user's plaintext password. |
| Sealed login state | The server's login state between the two login steps, encrypted and bound to `serverSetup`, the user identifier and a two-minute expiry. See [login](guide/usage.md#login). |
| Export key | A stable key available to the client after registration or login, never to the server. |
| Session key | A key derived by both client and server during a successful login. |
| `KSFConfig` | The Argon2id key-stretching profile; part of the credential format. See [Argon2id settings](guide/usage.md#argon2id-settings). |
| Native library | The Rust `cdylib` loaded by the .NET wrapper through C ABI functions. See [architecture](development/architecture.md). |

## Security model in one paragraph

OPAQUE keeps the password away from the server during registration and login. It does not make weak passwords safe, remove the need for TLS, or protect an application from endpoint compromise. Applications must still protect transport, account identifiers, server secrets, stored records and derived keys, and must never log passwords, protocol state, keys or `serverSetup`. Read [secure use and known limits](security/secure-use.md) before deploying.
