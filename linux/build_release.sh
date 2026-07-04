#!/bin/bash
#
# Build a portable, single-file Goblin AppImage.
#
# Usage: linux/build_release.sh [platform]
#   platform: 'x86_64' (default) or 'arm'
#
# Goblin links the Tor transport (embedded arti) IN-PROCESS, so the AppImage is
# one self-contained binary with no sidecar to embed or ship beside it.

set -euo pipefail

platform="${1:-x86_64}"
case "${platform}" in
  x86_64) arch="x86_64-unknown-linux-gnu"; appimage_arch="x86_64" ;;
  arm)    arch="aarch64-unknown-linux-gnu"; appimage_arch="aarch64" ;;
  *) echo "Usage: build_release.sh [platform]  (platform: 'x86_64' | 'arm')" >&2; exit 1 ;;
esac

# Repo root (this script lives in linux/).
BASEDIR=$(cd "$(dirname "$0")" && pwd)
cd "${BASEDIR}/.."

# Prefer the GRIM-canonical toolchains (zig + appimagetool from code.gri.mw/DEV);
# scripts/toolchain.sh fetches them and writes this env. Falls back to system
# installs when it's absent.
[ -f .toolchains/env.sh ] && source .toolchains/env.sh

rustup target add "${arch}"
command -v cargo-zigbuild >/dev/null || cargo install cargo-zigbuild

# Portable cross-build to glibc 2.17. Three zig-specific fixes:
#  - CRoaring's AVX512 path won't compile under zig's clang (evex512 error).
#  - OpenSSL is vendored in Cargo.toml, so no system libssl is needed.
#  - v4l2-sys (camera/QR backend) runs bindgen over linux/videodev2.h, a kernel
#    UAPI header missing from zig 0.12.1's glibc-2.17 sysroot; point bindgen at
#    the host's kernel headers. This only reads struct layouts — the actual libc
#    linkage stays glibc-2.17, so portability is unaffected.
export CFLAGS_x86_64_unknown_linux_gnu="-DCROARING_COMPILER_SUPPORTS_AVX512=0"
export CXXFLAGS_x86_64_unknown_linux_gnu="-DCROARING_COMPILER_SUPPORTS_AVX512=0"
export BINDGEN_EXTRA_CLANG_ARGS="${BINDGEN_EXTRA_CLANG_ARGS:-} -I/usr/include"
cargo zigbuild --release --target "${arch}.2.17"

# Assemble the AppDir: AppRun IS the goblin binary (Tor/arti linked in), plus the
# icon + desktop entry. Nothing else.
appdir="linux/Goblin.AppDir"
cp "target/${arch}/release/goblin" "${appdir}/AppRun"
chmod +x "${appdir}/AppRun"

out="target/${arch}/release/Goblin-${platform}.AppImage"
rm -f "target/${arch}/release/"*.AppImage
# Use the DEV appimagetool + type2 runtime when fetched, else the system tool.
appimagetool_bin="${GOBLIN_APPIMAGETOOL:-appimagetool}"
# The type2 runtime must match the target arch. env.sh sets GOBLIN_APPIMAGE_RUNTIME
# to the x86_64 runtime; for a non-x86_64 target use the sibling runtime-<arch>.
runtime_file="${GOBLIN_APPIMAGE_RUNTIME:-}"
if [ "${appimage_arch}" != "x86_64" ] && [ -n "${runtime_file}" ]; then
  runtime_file="$(dirname "${runtime_file}")/runtime-${appimage_arch}"
fi
runtime_arg=()
[ -n "${runtime_file}" ] && [ -e "${runtime_file}" ] && runtime_arg=(--runtime-file "${runtime_file}")
ARCH="${appimage_arch}" "${appimagetool_bin}" "${runtime_arg[@]}" "${appdir}" "${out}"
echo "built: ${out}"
