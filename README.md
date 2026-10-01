# Cyphra OPAQUE.Net

Secure password authentication for .NET using the [OPAQUE protocol](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/).

This project is a fork of [Vaultic-LLC/OPAQUE.Net](https://github.com/Vaultic-LLC/OPAQUE.Net). Its goal is to improve the library, keep it maintained, and strengthen its security over time.

OPAQUE is a password-authenticated key-exchange protocol: the server can authenticate a user without learning the user's password, and both sides derive a session key after login. The implementation combines a .NET API with a Rust native library.

## Quick start

Install the NuGet package:

```sh
dotnet add package Vaultic.OPAQUE.Net
```

Use one `OpaqueServer` and one `OpaqueClient` to complete registration once, then repeat the login flow whenever the user authenticates:

```csharp
using OPAQUE.Net;
using OPAQUE.Net.Types.Results;

var server = new OpaqueServer();
var client = new OpaqueClient();

// Generate once and store securely. It protects the server's long-term key.
server.CreateSetup(out string? serverSetup);

// Client: registration step 1
client.StartRegistration("correct horse battery staple",
    out StartClientRegistrationResult? registrationStart);

// Server: registration step 2
server.CreateRegistrationResponse(
    serverSetup!, "user-123", registrationStart!.RegistrationRequest,
    out string? registrationResponse);

// Client: registration step 3
client.FinishRegistration(
    "correct horse battery staple", registrationResponse!,
    registrationStart.ClientRegistrationState,
    out FinishClientRegistrationResult? registrationFinish);

// Store registrationFinish.RegistrationRecord with the user account.
```

For the complete registration and login sequence, result handling, identifiers, Argon2id settings, native builds, and security guidance, see the [documentation](docs/README.md).

## Supported platforms

The package targets .NET 8 and includes native binaries for Windows, Linux, and macOS on x64 and arm64.

The correct native library is selected by the .NET runtime identifier. See [supported platforms and builds](docs/building.md) for details.

## Project status

This is an actively maintained security-focused fork. Changes that affect cryptography, native interop, serialization, password handling, or supported runtimes require tests and careful review. This library does not replace a threat model or an application-level security review.

## Contributing and security

- Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.
- Report vulnerabilities privately according to [docs/security.md](docs/security.md).
- Documentation is also available in [Portuguese](README.pt-BR.md).

## License

See [LICENSE](LICENSE).
