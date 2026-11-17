[Docs](../README.md) › Development › **Building and testing**

# Building and testing

## Prerequisites

- .NET SDK 10 (builds both target frameworks; the library and the test project target `net8.0` and `net10.0`) and SDK 8 or its runtime to run the `net8.0` tests;
- `rustup` and the toolchain pinned in `rust-toolchain.toml`;
- the Rust target for the platform being built;
- Zig and `cargo-zigbuild` for the Linux builds (see [Linux compatibility build](#linux-compatibility-build)).

## Native assets

The Rust library is built for six runtime identifiers. Each build is copied into `.Net/OPAQUE.Net/` under a repository-specific name, which the project maps back to the name P/Invoke expects inside the package:

| RID | Rust target | Repository asset | Built with |
| --- | --- | --- | --- |
| `linux-x64` | `x86_64-unknown-linux-gnu` | `libopaque.so` | `cargo zigbuild`, glibc 2.17 floor |
| `linux-arm64` | `aarch64-unknown-linux-gnu` | `libopaque-linux-arm64.so` | `cargo zigbuild`, glibc 2.17 floor |
| `win-x64` | `x86_64-pc-windows-msvc` | `opaque.dll` | `cargo build`, static CRT |
| `win-arm64` | `aarch64-pc-windows-msvc` | `opaque-arm64.dll` | `cargo build`, static CRT |
| `osx-x64` | `x86_64-apple-darwin` | `libopaque-x64.dylib` | `cargo build` |
| `osx-arm64` | `aarch64-apple-darwin` | `libopaque.dylib` | `cargo build` |

These files are git-ignored build products: never commit them. What users get on each platform is described in [supported platforms](../guide/platforms.md).

## Native build on the host

```sh
cargo build --release --locked --target <rust-target>
```

Copy `target/<rust-target>/release/<library>` to the corresponding asset in `.Net/OPAQUE.Net/` from the table above and confirm the architecture:

```sh
file .Net/OPAQUE.Net/libopaque.so
```

`dotnet test` copies whichever native library is on disk. **Rebuild and copy it after every change under `src/` or to `Cargo.lock`**, or a stale binary makes the tests pass against old code.

## Linux compatibility build

A plain build on a recent distribution links against that distribution's glibc (2.39 on Ubuntu 24.04), and the library would refuse to load on older systems. Zig acts as the cross-linker with its own glibc stubs, which makes an explicit 2.17 floor possible. Install Zig and `cargo-zigbuild` from the hash-pinned wheels CI uses (not `cargo install`, which cannot be checksum-pinned), add the Rust targets, and use the `.2.17` suffix:

```sh
python3 -m pip install --user --require-hashes -r .github/requirements-zig.txt
rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
cargo zigbuild --release --locked --target x86_64-unknown-linux-gnu.2.17
cargo zigbuild --release --locked --target aarch64-unknown-linux-gnu.2.17
```

Check the floor the same way CI does: the highest `GLIBC_` version printed must be 2.17 or lower.

```sh
objdump -T target/x86_64-unknown-linux-gnu/release/libopaque.so | grep -oE 'GLIBC_[0-9.]+' | sort -Vu | tail -1
```

Never ship a plain native build from a newer distribution.

## Tests

The commands CI runs, also listed in [CONTRIBUTING.md](../../CONTRIBUTING.md#local-workflow):

```sh
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
dotnet test .Net/Test/Test.csproj --configuration Release
```

The Rust tests cover the protocol, sealed-state expiry and clock skew, and FFI string and handle handling. The .NET tests (MSTest) cover:

- registration and login with each KSF profile;
- incorrect passwords and identifier or KSF mismatches;
- unknown users and tampered or garbage input;
- sealed-state binding to the user, tampering and single use (`LoginStateReplayCache`);
- argument validation before native invocation;
- redaction of result types;
- native library loading.

## Continuous integration

The `Build and test` workflow (`.github/workflows/build-and-test.yaml`) runs on every pull request into `main` and `develop`, and is reused by the release workflow. For each of the six RIDs it:

1. builds the native library;
2. checks the architecture of the binary, the glibc floor on Linux, and the DLL imports on Windows;
3. runs the Rust and .NET tests.

It also audits dependencies (`cargo audit`, `cargo deny check`) and verifies the package layout with `scripts/pack-and-verify.sh`.

## Adding a platform

Update the [native assets](#native-assets) table and all of the following together:

1. the native asset entries and validation in `.Net/OPAQUE.Net/OPAQUE.Net.csproj`;
2. the build/test matrix in `.github/workflows/build-and-test.yaml`;
3. the staging list and expected package entries in `scripts/pack-and-verify.sh` (run by `publish.yaml` and on every pull request);
4. the RID table in [supported platforms](../guide/platforms.md) and the tests.

---

**Previous:** [Architecture](architecture.md) · **Next:** [Packaging and releases](releasing.md)
