#!/bin/bash
#
# Build a portable, single-file Goblin AppImage.
#
# Usage: linux/build_release.sh [platform]
#   platform: 'x86_64' (default) or 'arm'
#
# Goblin links the Nym SDK IN-PROCESS (src/nym/), so the AppImage is one
# self-contained binary with no sidecar to embed or ship beside it.

set -euo pipefail

platform="${1:-x86_64}"
case "${platform}" in
  x86_64) arch="x86_64-unknown-linux-gnu" ;;
  arm)    arch="aarch64-unknown-linux-gnu" ;;
  *) echo "Usage: build_release.sh [platform]  (platform: 'x86_64' | 'arm')" >&2; exit 1 ;;
esac

# Repo root (this script lives in linux/).
BASEDIR=$(cd "$(dirname "$0")" && pwd)
cd "${BASEDIR}/.."

rustup target add "${arch}"
command -v cargo-zigbuild >/dev/null || cargo install cargo-zigbuild

# Portable cross-build to glibc 2.17. Two zig-specific fixes:
#  - CRoaring's AVX512 path won't compile under zig's clang (evex512 error).
#  - OpenSSL is vendored in Cargo.toml, so no system libssl is needed.
export CFLAGS_x86_64_unknown_linux_gnu="-DCROARING_COMPILER_SUPPORTS_AVX512=0"
export CXXFLAGS_x86_64_unknown_linux_gnu="-DCROARING_COMPILER_SUPPORTS_AVX512=0"
cargo zigbuild --release --target "${arch}.2.17"

# Assemble the AppDir: AppRun IS the goblin binary (Nym SDK linked in), plus the
# icon + desktop entry. Nothing else.
appdir="linux/Goblin.AppDir"
cp "target/${arch}/release/goblin" "${appdir}/AppRun"
chmod +x "${appdir}/AppRun"

out="target/${arch}/release/Goblin-${platform}.AppImage"
rm -f "target/${arch}/release/"*.AppImage
ARCH=x86_64 appimagetool "${appdir}" "${out}"
echo "built: ${out}"
