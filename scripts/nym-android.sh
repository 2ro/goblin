#!/bin/bash
# Cross-compile the bundled Nym SOCKS5 sidecar (nym-socks5-client) for Android.
# scripts/android.sh copies the result into the APK's jniLibs as
# libnym_socks5_client.so so Goblin can launch the mixnet client on-device.
#
# Usage: NYM_SRC=../nym scripts/nym-android.sh [v7|v8|x86|all]
#   NYM_SRC  path to the Nym workspace checkout (default: ../nym)
# Requires: ANDROID_NDK_HOME, rustup android targets, cargo-ndk.
#
# Note: the sidecar is patched to use preconfigured webpki roots on Android
# (common/http-api-client/src/registry.rs) — the default rustls platform
# verifier needs the app's JNI context, which a standalone process lacks.
set -e

NYM_SRC="${NYM_SRC:-../nym}"
WHICH="${1:-all}"

build() {
  local abi="$1"
  echo ">> building nym-socks5-client for ${abi}"
  ( cd "${NYM_SRC}" && cargo ndk -t "${abi}" build --release -p nym-socks5-client )
}

case "${WHICH}" in
  v7)  build armeabi-v7a ;;
  v8)  build arm64-v8a ;;
  x86) build x86_64 ;;
  all) build arm64-v8a; build x86_64; build armeabi-v7a ;;
  *)   echo "usage: $0 [v7|v8|x86|all]"; exit 1 ;;
esac
echo "done — sidecars in ${NYM_SRC}/target/<triple>/release/nym-socks5-client"
