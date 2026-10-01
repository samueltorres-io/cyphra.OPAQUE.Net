# Building and testing

The package targets .NET 8 and ships the Rust native library for six runtime identifiers:

| RID | Rust target | Repository asset |
| --- | --- | --- |
| `linux-x64` | `x86_64-unknown-linux-gnu` | `libopaque.so` |
| `linux-arm64` | `aarch64-unknown-linux-gnu` | `libopaque-linux-arm64.so` |
| `win-x64` | `x86_64-pc-windows-msvc` | `opaque.dll` |
| `win-arm64` | `aarch64-pc-windows-msvc` | `opaque-arm64.dll` |
| `osx-x64` | `x86_64-apple-darwin` | `libopaque-x64.dylib` |
| `osx-arm64` | `aarch64-apple-darwin` | `libopaque.dylib` |

The Linux binaries are built with a glibc 2.17 compatibility floor. The `Build and test` workflow builds the Rust library, runs Rust tests, checks the architecture and glibc floor, and runs the .NET test suite. It is the CI gate for pull requests into `main`.

## Prerequisites

- .NET SDK 8 or later;
- `rustup` and the toolchain pinned in `rust-toolchain.toml`;
- the Rust target for the platform being built;
- `cargo-zigbuild` and Zig for Linux cross-compilation.

## Tests

```sh
cargo test --locked
dotnet test .Net/Test/Test.csproj --configuration Release
```

The tests cover successful registration and login, RFC-recommended and custom KSF settings, incorrect passwords, identifier mismatches, invalid parameters, and validation before native invocation.

## Native build on the host

```sh
cargo build --release --locked --target <rust-target>
```

Copy the output to the corresponding asset in `.Net/OPAQUE.Net/`, using the table above. Then run the .NET tests. Confirm the architecture before committing a native file:

```sh
file .Net/OPAQUE.Net/libopaque.so
```

## Linux compatibility build

Install `cargo-zigbuild`, add the Rust targets, and use the `.2.17` suffix:

```sh
cargo install cargo-zigbuild
rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
cargo zigbuild --release --locked --target x86_64-unknown-linux-gnu.2.17
cargo zigbuild --release --locked --target aarch64-unknown-linux-gnu.2.17
```

Do not replace the committed Linux libraries with a plain native build from a newer distribution; it may require a newer glibc than supported.

## Packaging

```sh
dotnet pack .Net/OPAQUE.Net/OPAQUE.Net.csproj --configuration Release --output ./artifacts
```

The project fails packing when a required native asset is missing. Inspect the package and confirm all six runtime assets are present before publishing. The `publish` workflow performs the same package verification and publishes only after a release or manual dispatch.

## Adding a platform

Update the runtime asset table and all of the following together:

1. the native asset entries and validation in `OPAQUE.Net.csproj`;
2. the build/test matrix in `.github/workflows/build-and-test.yaml`;
3. the package verification in `.github/workflows/publish.yaml`;
4. the documentation and tests.
