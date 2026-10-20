#!/usr/bin/env bash
# F-06 regression check: `dotnet pack` must refuse outside CI, and must pass with the explicit opt-in.
set -uo pipefail
proj=".Net/OPAQUE.Net/OPAQUE.Net.csproj"
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

# Simulate a local machine even when this runs on a CI runner.
if env -u GITHUB_ACTIONS dotnet pack "$proj" -o "$out" >"$out/log" 2>&1; then
  echo "FAIL: local pack succeeded without OpaqueAllowLocalPack"; exit 1
fi
grep -q "Refusing to pack" "$out/log" || { echo "FAIL: pack failed for another reason"; cat "$out/log"; exit 1; }
echo "OK: local pack refused"
