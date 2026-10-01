# Contributing to Cyphra OPAQUE.Net

Thank you for helping improve this security-focused fork of [Vaultic-LLC/OPAQUE.Net](https://github.com/Vaultic-LLC/OPAQUE.Net). Contributions are welcome, especially tests, documentation, portability fixes, and carefully reviewed hardening changes.

## Before you start

Read the project documentation in [`docs/`](docs/README.md), especially:

- [`docs/architecture.md`](docs/architecture.md) for the managed/native boundary;
- [`docs/security.md`](docs/security.md) for vulnerability reporting and security expectations;
- [`docs/building.md`](docs/building.md) for the native build and test workflow.

Please search existing issues and pull requests before starting larger work. For a substantial API, protocol, or packaging change, open an issue first so the design can be discussed before implementation.

## Development requirements

- .NET SDK 8 or later;
- Rust and `rustup`, using the version pinned by `rust-toolchain.toml`;
- the Rust targets required for the platform you are building;
- a native library for the host runtime, or a build of the Rust library as described in [`docs/building.md`](docs/building.md).

The repository contains the managed wrapper in `.Net/OPAQUE.Net`, the Rust implementation and C ABI in `src/`, and MSTest coverage in `.Net/Test`.

## Local workflow

Run the Rust tests:

```sh
cargo test --locked
```

Run the .NET tests:

```sh
dotnet test .Net/Test/Test.csproj --configuration Release
```

Build the package locally:

```sh
dotnet pack .Net/OPAQUE.Net/OPAQUE.Net.csproj --configuration Release
```

Before opening a pull request, run the relevant tests on every platform affected by the change. Do not commit files from `bin/`, `obj/`, or `target/`.

## Security-sensitive changes

Treat the following as security-sensitive: password or identifier handling, protocol state transitions, Argon2id parameters, random number generation, serialization, FFI signatures, `DllImport` declarations, `SafeHandle` ownership, native library loading, and package runtime assets.

For these changes:

1. Explain the threat or failure mode in the pull request.
2. Add a regression test that fails before the change.
3. Keep the managed and native sides in sync.
4. Avoid logging passwords, registration records, session keys, or private server setup values.
5. Document compatibility and migration impact.

Never include real passwords, production credentials, private keys, registration records, or session keys in issues, tests, commits, or pull requests.

## Pull requests

Use a focused branch and a clear title. A good pull request includes:

- what changed and why;
- the security or compatibility impact;
- tests executed and their results;
- platform/runtime coverage when native code or binaries are involved;
- documentation updates when behavior or public API changes.

Keep unrelated formatting or dependency changes out of the same pull request. Reviewers should be able to trace each behavior change to a test or an explicit design decision.

The `Build and test` GitHub Actions workflow is the required CI gate for pull requests into `main`. The `publish` workflow is reserved for creating and publishing NuGet packages after a release is prepared.

## Commits and releases

Use imperative, descriptive commit messages, for example:

```text
Harden native input validation
Document the login flow
```

Do not change package versions or publish releases in a normal feature pull request unless the change is specifically part of a release task. Never publish a package from a local build containing unreviewed native binaries.

## Code of conduct

Be respectful, precise, and constructive. Security discussions should focus on reproducible behavior, impact, and remediation rather than blame.
