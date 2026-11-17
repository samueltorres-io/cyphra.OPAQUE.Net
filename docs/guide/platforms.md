[Docs](../README.md) › Guide › **Supported platforms**

# Supported platforms

The package targets .NET 8 and .NET 10 (`net8.0` and `net10.0`) and ships the Rust native library for six runtime identifiers (RIDs). The right one is picked by the .NET runtime identifier of your application; there is nothing to configure.

| RID | Operating system | Notes |
| --- | --- | --- |
| `linux-x64` | Linux (glibc) | glibc 2.17 or newer |
| `linux-arm64` | Linux (glibc) | glibc 2.17 or newer |
| `win-x64` | Windows | C runtime linked statically: imports only system DLLs |
| `win-arm64` | Windows | C runtime linked statically: imports only system DLLs |
| `osx-x64` | macOS (Intel) | |
| `osx-arm64` | macOS (Apple silicon) | |

How each binary is built is in [Building and testing](../development/building.md#native-assets).

## Unsupported runtime identifiers

Only the six RIDs above have a native library. Linux support is **glibc only**: `linux-musl-x64`/`linux-musl-arm64` (Alpine), `win-x86`, `linux-arm`, `linux-x86`, Android, iOS, tvOS, browser and WASI have none, and the glibc `libopaque.so` cannot load on musl.

- **Build time.** Restoring or publishing for one of them (`-r <rid>`) emits warning `OPAQUE001` naming the RID. To make it fail the build, add `<WarningsAsErrors>$(WarningsAsErrors);OPAQUE001</WarningsAsErrors>` to your project.
- **Run time.** The app starts, but the first call throws `DllNotFoundException` (with the probed directories) or `BadImageFormatException`. These are never mapped to a failed login (see [failure handling](usage.md#failure-handling)).
- **Alpine.** Use a glibc base image (for example the Debian-based `mcr.microsoft.com/dotnet/runtime` or `aspnet` images). A musl binary is not shipped; adding one is described in [adding a platform](../development/building.md#adding-a-platform).

## How the native library is loaded

The native library is loaded only from the directories the .NET host resolved for your application: the `runtimes/<rid>/native` assets, the application directory and the assembly directory. The operating-system search path (`LD_LIBRARY_PATH`, `PATH`, the working directory) is never consulted, so a library planted there is not picked up. A missing or unloadable library throws `DllNotFoundException` listing the probed directories.

If another component registers a `DllImport` resolver for this assembly first, that resolver decides where the library comes from and the restriction above no longer applies; the library writes a trace warning when this happens. Keep the application directory unwritable by untrusted users. Details in [native library loading](../security/secure-use.md#design-notes-and-known-limits).

## Verifying a release

Each release package carries signed build provenance (SLSA, via GitHub artifact attestations) and a `.sha256` file attached to the GitHub release. Verify a downloaded package with:

```sh
gh attestation verify Cyphra.OPAQUE.Net.<version>.nupkg -R samueltorres-io/cyphra.OPAQUE.Net
```

---

**Previous:** [Usage and protocol flow](usage.md) · **Next:** [API reference](../reference/api.md)
