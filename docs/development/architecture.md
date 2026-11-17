[Docs](../README.md) › Development › **Architecture**

# Architecture

Cyphra OPAQUE.Net has three layers:

```mermaid
flowchart TB
    App["Your application"] --> API
    API[".NET API — .Net/OPAQUE.Net<br/>OpaqueClient, OpaqueServer, results,<br/>validation, SafeHandle ownership"]
    API -- "C ABI (cdecl), DllImport opaque" --> Bridge
    Bridge["C ABI bridge — src/lib.rs, src/types.rs, src/csharp.rs<br/>exported functions, handle registry,<br/>string conversion, panic boundary"]
    Bridge --> Impl
    Impl["OPAQUE implementation — src/, src/seal.rs<br/>opaque-ke 3.0, Argon2id, sealed login state"]
```

1. **.NET API**: `OpaqueClient`, `OpaqueServer`, result types, validation, and safe-handle ownership in `.Net/OPAQUE.Net`.
2. **C ABI bridge**: the exported Rust functions (`src/lib.rs`, `src/types.rs`) and the string and handle helpers in `src/csharp.rs` convert protocol inputs and outputs across the native boundary. Every export runs inside a panic boundary.
3. **OPAQUE implementation**: Rust code in `src/`, backed by `opaque-ke` 3.0, Argon2, randomness, and serialization dependencies.

## Native boundary

**Loading.** The C# wrapper calls the native library with `DllImport("opaque", CallingConvention = CallingConvention.Cdecl)`. The library is loaded by `NativeLibraryResolver`, only from the directories the .NET host resolved for the application (see [native library loading](../security/secure-use.md#design-notes-and-known-limits)).

- The resolver is registered from a module initializer, so it is in place before the first P/Invoke of any type without an init call. This is the case analyzer rule CA2255 allows for, and its suppression is scoped to that method.
- Search entries that are not fully qualified are skipped, because they would resolve against the current working directory.
- As defense in depth (CA5392), the assembly sets `DefaultDllImportSearchPaths(AssemblyDirectory)`: if the resolver ever did not run, the runtime's own probing stays limited to the assembly directory.
- The csproj gives every RID's binary the same canonical name in the build output and in `runtimes/<rid>/native`, so the resolver looks for one name.

**Ownership.** Native strings and result objects come back through `SafeHandle`-based wrappers and are released by the matching Rust functions. A NULL result handle is the native failure value and is never passed to a getter.

- **Result handles** are never-reused tokens that own their result, not memory addresses. Once a result is freed, its handle stays dead even after the allocator reuses the memory: a repeated or stale release, or a token presented as the wrong result type, finds nothing. Tokens come from a `usize` counter, which would need 2^64 results (2^32 on a 32-bit host) to wrap.
- **String handles** are tracked in a registry of live strings, so a repeated release is ignored instead of freeing memory twice. Strings are wiped before they are freed, because they may carry session or export keys.
- **Locks.** Each registry lock is held while a handle is read or released, so a concurrent release cannot free it mid-read. Getters copy the field under the lock and build the C string after releasing it, so the lock is held only for the copy. The locks recover from poisoning: a panic while one is held cannot leave the registry in a state that matters, whereas treating poison as fatal would make every later call fail for the rest of the process.
- **.NET side.** `StringHandle` wipes its intermediate byte buffer after decoding. The returned .NET string is immutable and cannot be wiped.

**Inputs.**

- Input strings must be valid UTF-8, NUL-terminated values no larger than 64 KiB. The native side scans with `strnlen` bounded at 64 KiB + 1, so an unterminated value cannot cause an unbounded read; the caller must still pass a readable pointer, which portable Rust cannot verify.
- Protocol messages are base64url without padding, decoded canonically (no padding, no spare bits), so each value has exactly one string form.
- Registration requests must be canonical: opaque-ke 3.0 accepts trailing bytes only for `RegistrationRequest` (voprf `take_ext`), so the bridge rejects them there. Every other message it parses is exact-size.
- Passwords and identifiers have a 1 KiB (UTF-8 bytes) limit, and the C# wrapper rejects embedded NUL and unpaired surrogates.
- Passwords and `serverSetup` are passed as pinned UTF-8 buffers that are zeroed after the call.
- `KSFConfig` crosses as numbers: the profile as `i32` and the costs as `u32`.
- `null`, invalid UTF-8, oversized values and null result handles fail the operation instead of being interpreted as empty strings.

Any change to an exported function, string encoding, ownership rule, or result layout must update both sides and include tests.

**Packaging.** The package stores platform-specific binaries under `runtimes/<rid>/native/`. The .NET project maps the repository file names (see [native assets](building.md#native-assets)) to the name P/Invoke probes for on each OS. The managed assembly targets `net8.0` and `net10.0`.

## State and secrets

Protocol state is carried between individual client and server calls. Server login state is sealed (authenticated encryption keyed from `serverSetup`, bound to the user identifier; see `src/seal.rs` and [sealed login state](../security/secure-use.md#sealed-login-state)), which keeps the server stateless. The unsealed state never crosses the native boundary.

The library does not provide a database, session store, transport, account service, or secret manager. The application owns:

- protecting `serverSetup`;
- associating `RegistrationRecord` with the correct account;
- authenticating the transport and authorizing the resulting session;
- limiting login attempts and monitoring abuse;
- securely handling `ExportKey` and session keys;
- providing atomic first-use storage for `tryConsume` when it runs more than one instance.

## Error boundary

Managed validation rejects empty required inputs, oversized or malformed strings, and unsafe custom KSF values before invoking native code. A password or identifier with more chars than the byte limit is rejected without encoding it, since every char takes at least one UTF-8 byte.

Native protocol failures become a failed operation (`false` and a null result). The Rust error type is deliberately payload-free: a cause attached to it could reach callers and tell an attacker which protocol step rejected their input, so every failure is the same value and becomes an empty result. A failed login finish (wrong password, identifiers, tampered response) is an expected outcome and is reported the same way.

The unknown-user path is kept the same shape as the real one. A stored record that does not decode (corrupt, legacy, placeholder, trailing bytes) takes the same dummy path as an absent record, and the absent-record check compares the exact length instead of re-serializing the key, so it adds no work that only real records do (see [account-existence timing](../security/secure-use.md#design-notes-and-known-limits)). `FunctionHelper.TryExecute` rethrows process-level faults (out of memory, stack overflow, marshalling, SEH) instead of reporting them as a failed login. Server login additionally exposes an infrastructure exception through an output parameter, so applications can keep internal diagnostics separate from externally safe authentication responses.

When modifying this boundary, test invalid inputs, incorrect passwords, identifier mismatches, KSF mismatches, native failures, and native resource cleanup.

## Dependency constraints

- **`generic-array` 0.14.** Version 0.14.9 and later deprecate the whole 0.14 API in favour of 1.x, but opaque-ke 3.0's `Ksf` trait is defined over 0.14 types. The `#[allow(deprecated)]` is therefore scoped to the `Ksf` implementation, not the crate, so deprecations elsewhere still fail the build. It goes away with the opaque-ke upgrade (5.x uses `generic-array` 1 and `hybrid-array`).
- **`KSFConfigType` values** (`0`, `1`, `2`) are part of the ABI: do not reorder or renumber them.

## ABI evolution

The current ABI is kept for compatibility with released native assets. Its `char*` inputs require a readable NUL-terminated buffer, a limitation of the original contract. Result handles are already opaque tokens. A future versioned ABI should also use `(pointer, length)` input pairs, explicit status codes, and a status-to-public-error mapping in .NET. New functionality belongs on that versioned surface rather than changing existing symbols in place.

---

**Next:** [Building and testing](building.md) · **See also:** [Secure use and known limits](../security/secure-use.md)
