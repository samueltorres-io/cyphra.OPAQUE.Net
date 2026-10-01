# Architecture

Cyphra OPAQUE.Net has three layers:

1. **.NET API** — `OpaqueClient`, `OpaqueServer`, result types, validation, and safe-handle ownership in `.Net/OPAQUE.Net`.
2. **C ABI bridge** — exported Rust functions in `src/csharp.rs` convert protocol inputs and outputs across the native boundary.
3. **OPAQUE implementation** — Rust code in `src/`, backed by `opaque-ke`, Argon2, randomness, and serialization dependencies.

## Native boundary

The C# wrapper calls the native library with `DllImport("opaque", CallingConvention = CallingConvention.Cdecl)`. Native strings are returned through `SafeHandle`-based wrappers and released by the matching Rust functions. Input strings must be valid UTF-8, NUL-terminated values no larger than 64 KiB; passwords and identifiers have a 1 KiB limit. `null`, invalid UTF-8, oversized values, and null result handles fail the operation instead of being interpreted as empty strings. Any change to an exported function, string encoding, ownership rule, or result layout must update both sides and include tests.

The package stores platform-specific binaries under `runtimes/<rid>/native/`. The .NET project selects the binary matching the host runtime identifier and maps repository-specific filenames back to the name expected by P/Invoke.

## State and secrets

Protocol state is deliberately carried between individual client and server calls. The library does not provide a database, session store, transport, account service, or secret manager. The application owns:

- protecting `serverSetup`;
- associating `RegistrationRecord` with the correct account;
- authenticating the transport and authorizing the resulting session;
- limiting login attempts and monitoring abuse;
- securely handling `ExportKey` and session keys.

## Error boundary

Managed validation rejects empty required inputs and unsafe custom KSF values before invoking native code. Native protocol failures are converted into a failed operation. Server login additionally exposes an infrastructure exception through an output parameter so applications can distinguish internal diagnostics from externally safe authentication responses.

When modifying this boundary, test invalid inputs, incorrect passwords, identifier mismatches, KSF mismatches, native failures, and native resource cleanup.
