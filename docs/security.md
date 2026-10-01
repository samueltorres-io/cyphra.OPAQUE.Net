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
- avoid revealing whether a user exists or which protocol step failed;
- pin or validate the server public key when the application threat model requires it;
- keep native assets aligned with their runtime identifiers.

## Security-sensitive changes

Changes to cryptography, protocol state, random number generation, password handling, Argon2id settings, serialization, native interop, memory ownership, or package assets require regression tests and review. See [`CONTRIBUTING.md`](../CONTRIBUTING.md).
