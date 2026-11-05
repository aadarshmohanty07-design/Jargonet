#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/meshchat/build-dist-linux"
STAGE="$ROOT/dist/meshchat-linux-x86_64"
ARCHIVE="$ROOT/dist/meshchat-linux-x86_64.tar.gz"

mkdir -p "$ROOT/dist"
rm -rf "$STAGE"
rm -f "$ARCHIVE"

cmake_args=(
  -S "$ROOT/meshchat"
  -B "$BUILD"
  -G Ninja
  -DCMAKE_BUILD_TYPE=Release
  -DMESHCHAT_STATIC_RUNTIME=ON
  -DMESHCHAT_STATIC_SODIUM=ON
)
if [[ -n "${JARGONET_SODIUM_ROOT:-}" ]]; then
  cmake_args+=("-DJARGONET_SODIUM_ROOT=$JARGONET_SODIUM_ROOT")
fi

cmake "${cmake_args[@]}"
cmake --build "$BUILD" -j

mkdir -p "$STAGE/lib"
cp "$BUILD/meshchat" "$STAGE/meshchat"
cp "$ROOT/meshchat/dist/README.txt" "$STAGE/README.txt"
cp "$ROOT/meshchat/dist/run.sh" "$STAGE/run.sh"
chmod +x "$STAGE/meshchat" "$STAGE/run.sh"

# Bundle only the non-system libraries that are actually needed. A static
# libsodium (preferred by the build) means this list is empty.
if command -v ldd >/dev/null 2>&1; then
  while IFS= read -r lib; do
    case "$(basename "$lib")" in
      libsodium.so*|libstdc++.so*|libgcc_s.so*)
        cp -L "$lib" "$STAGE/lib/"
        ;;
    esac
  done < <(ldd "$STAGE/meshchat" | awk '{print $3}' | grep '^/' || true)
fi

"$STAGE/meshchat" --version >/dev/null 2>&1 || {
  echo "warning: bundled binary did not execute on this build host (cross-check on the target)" >&2
}

tar -C "$ROOT/dist" -czf "$ARCHIVE" meshchat-linux-x86_64
echo "$ARCHIVE"
