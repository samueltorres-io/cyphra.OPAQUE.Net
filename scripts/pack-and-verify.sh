#!/usr/bin/env bash
# Stages the freshly built native libraries, packs the NuGet package and asserts it carries every
# supported runtime. Used by publish.yaml (the release) and build-and-test.yaml (every PR), so a pack
# that silently loses a platform fails in the PR instead of at release time.
#
# usage: scripts/pack-and-verify.sh <artifacts-dir> <out-dir> [version]
#   <artifacts-dir>  where the native-<rid> artifacts were downloaded (one subdirectory per RID)
#   <out-dir>        where the .nupkg is written
#   [version]        overrides the csproj <Version> (the release passes the tag's version)
# Must run in GitHub Actions: the csproj refuses to pack anywhere else (see docs/building.md).
set -euo pipefail

artifacts=${1:?artifacts dir}
out=${2:?output dir}
version=${3:-}
proj=".Net/OPAQUE.Net"

# artifact subdirectory/file -> name the csproj expects next to it
stage=(
  "native-linux-x64/libopaque.so:libopaque.so"
  "native-linux-arm64/libopaque-linux-arm64.so:libopaque-linux-arm64.so"
  "native-win-x64/opaque.dll:opaque.dll"
  "native-win-arm64/opaque-arm64.dll:opaque-arm64.dll"
  "native-osx-x64/libopaque-x64.dylib:libopaque-x64.dylib"
  "native-osx-arm64/libopaque.dylib:libopaque.dylib"
)
for pair in "${stage[@]}"; do
  cp "$artifacts/${pair%%:*}" "$proj/${pair##*:}"
done

dotnet pack "$proj/OPAQUE.Net.csproj" --configuration Release --output "$out" ${version:+-p:Version=$version}

expected=(
  runtimes/linux-x64/native/libopaque.so
  runtimes/linux-arm64/native/libopaque.so
  runtimes/win-x64/native/opaque.dll
  runtimes/win-arm64/native/opaque.dll
  runtimes/osx-x64/native/libopaque.dylib
  runtimes/osx-arm64/native/libopaque.dylib
  build/Cyphra.OPAQUE.Net.targets
  buildTransitive/Cyphra.OPAQUE.Net.targets
  lib/net8.0/OPAQUE.Net.dll
  lib/net10.0/OPAQUE.Net.dll
)

shopt -s nullglob
packages=("$out"/*.nupkg)
[ ${#packages[@]} -eq 1 ] || { echo "::error::expected exactly one .nupkg in $out, found ${#packages[@]}"; exit 1; }
echo "Inspecting ${packages[0]##*/}"

entries=$(unzip -Z1 "${packages[0]}" | tr '\\' '/')
missing=()
for e in "${expected[@]}"; do
  grep -qxF "$e" <<<"$entries" || missing+=("$e")
done
if [ ${#missing[@]} -gt 0 ]; then
  echo "Package contains:"; sed 's/^/  /' <<<"$entries"
  echo "::error::Package is missing: ${missing[*]}"
  exit 1
fi
echo "All ${#expected[@]} expected entries are present."
