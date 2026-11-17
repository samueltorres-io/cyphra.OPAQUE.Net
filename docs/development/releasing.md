[Docs](../README.md) › Development › **Packaging and releases**

# Packaging and releases

## Packaging rules

Releases are packed only by the `publish` workflow, from native libraries built by CI for that exact commit. Outside GitHub Actions `dotnet pack` fails on purpose, because the untracked native files on your disk may be stale.

The project also refuses to pack when any of the six [native assets](building.md#native-assets) is missing, so a package can never silently lose a platform. `scripts/pack-and-verify.sh` then checks the package contents: both `lib/net8.0` and `lib/net10.0`, the six `runtimes/<rid>/native/` files with the right architectures, and no unexpected entries.

For a throwaway local package, add `-p:OpaqueAllowLocalPack=true` (all six files must exist). Never publish it.

```sh
dotnet pack .Net/OPAQUE.Net/OPAQUE.Net.csproj --configuration Release --output ./artifacts -p:OpaqueAllowLocalPack=true
```

## Release checklist

1. On `develop`, update `<Version>` in `.Net/OPAQUE.Net/OPAQUE.Net.csproj` and add the version's section (with migration notes for breaking changes) to [CHANGELOG.md](../../CHANGELOG.md).
2. Merge `develop` into `main` through a pull request with a green `Build and test`.
3. Create a GitHub release on the merge commit on `main`, with a **tag in the form `vX.Y.Z`** (for example `v2.0.0`; a pre-release looks like `v2.1.0-rc.1`).
   - A tag without the leading `v` (for example `2.0.0`) fails the workflow before packing.
   - To fix it, delete the release and the tag, then create them again with the `v`.
4. Publishing the release starts the `publish` workflow. Follow it in the Actions tab.

## The `publish` workflow

`.github/workflows/publish.yaml` runs only when a GitHub release is **published**. It:

1. reruns the full [Build and test](building.md#continuous-integration) workflow for the tagged commit;
2. refuses to continue unless the tagged commit is on `main`;
3. packs with the version taken from the tag (it overrides the csproj `<Version>`) and verifies the package with `scripts/pack-and-verify.sh`;
4. signs SLSA build provenance for the `.nupkg`, and attaches the package and its SHA-256 checksum to the GitHub release;
5. pushes the package to NuGet.org using OIDC (trusted publishing).

Release assets are uploaded without `--clobber`, so a rerun cannot make GitHub and NuGet diverge. Users can verify a package as described in [verifying a release](../guide/platforms.md#verifying-a-release).

---

**Previous:** [Building and testing](building.md) · **Back to:** [Documentation index](../README.md)
