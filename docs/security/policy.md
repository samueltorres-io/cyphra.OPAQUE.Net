[Docs](../README.md) › Security › **Security policy**

# Security policy

Cyphra OPAQUE.Net is a security-focused fork of [Vaultic-LLC/OPAQUE.Net](https://github.com/Vaultic-LLC/OPAQUE.Net). Our goal is to improve the library and make it safer to use and maintain. Security fixes are coordinated privately whenever possible.

## Supported versions

The latest published version on the default branch is the supported version. Older versions may not receive security fixes; upgrade (see the [changelog](../../CHANGELOG.md)) before reporting a problem that a newer release may have fixed.

## Reporting a vulnerability

Do not open a public issue for an unpatched vulnerability. Report it privately at <https://github.com/samueltorres-io/cyphra.OPAQUE.Net/security/advisories/new> (GitHub private vulnerability reporting). If that form is unavailable, open a public issue that asks for a private contact and contains no technical details.

Include:

- affected commit, version, platform, and runtime identifier;
- a concise impact statement;
- reproduction steps or a minimal proof of concept;
- whether exploitation requires local access, a malicious server, a malicious client, or control of the transport;
- any proposed mitigation.

Do not include real passwords, production secrets, server setup values, registration records, session keys, or personal data.

We will acknowledge receipt, reproduce the report, coordinate a fix and disclosure timeline, and credit the reporter when permission is given.

## Security-sensitive changes

Changes to cryptography, protocol state, random number generation, password handling, Argon2id settings, serialization, native interop, memory ownership, or package assets require regression tests and review. See [CONTRIBUTING.md](../../CONTRIBUTING.md#security-sensitive-changes) and the [architecture](../development/architecture.md) of the native boundary.

---

**See also:** [Secure use and known limits](secure-use.md)
