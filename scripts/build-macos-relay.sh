#!/usr/bin/env bash
# Build "Prism Launcher.app" (home-relay fork) on a Mac.
#
# Most people should use the GitHub Actions workflow instead ("Build macOS app (home relay)"): it
# needs nothing installed on the Mac. This script is for building locally on an Apple-silicon or
# Intel Mac that has Xcode command line tools and Homebrew.
#
#   ./scripts/build-macos-relay.sh            # builds for this Mac's CPU
#
# Result: ./dist-macos/Prism Launcher.app  (ad-hoc signed, with the auto-updater removed)
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$(uname)" != "Darwin" ]]; then
  echo "This script builds the macOS app and must be run on a Mac." >&2
  exit 1
fi
command -v brew >/dev/null || { echo "Homebrew is required: https://brew.sh" >&2; exit 1; }

echo "==> Installing build dependencies with Homebrew"
brew install cmake ninja extra-cmake-modules qt@6 cmark tomlplusplus quazip libarchive zlib qrencode temurin@17 || true

echo "==> Fetching bundled libraries"
git submodule update --init --recursive

QT_PREFIX="$(brew --prefix qt@6)"
export JAVA_HOME="$(/usr/libexec/java_home -v 17)"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-12.0}"

BUILD_DIR="build-macos"
INSTALL_DIR="dist-macos"
rm -rf "$BUILD_DIR" "$INSTALL_DIR"

# MACOSX_SPARKLE_* empty = no Sparkle auto-updater (it would contact prismlauncher.org directly,
# bypassing the relay, and could replace this fork with stock Prism).
echo "==> Configuring"
cmake -S . -B "$BUILD_DIR" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$QT_PREFIX;$(brew --prefix)" \
  -DLauncher_QT_VERSION_MAJOR=6 \
  -DLauncher_BUILD_PLATFORM=home-relay \
  -DMACOSX_SPARKLE_UPDATE_FEED_URL= \
  -DMACOSX_SPARKLE_UPDATE_PUBLIC_KEY= \
  -DCMAKE_INSTALL_PREFIX="$PWD/$INSTALL_DIR"

echo "==> Building (this takes a while)"
cmake --build "$BUILD_DIR"

echo "==> Running tests"
ctest --test-dir "$BUILD_DIR" --output-on-failure

echo "==> Installing and signing"
cmake --install "$BUILD_DIR"
cd "$INSTALL_DIR"
chmod +x "PrismLauncher.app/Contents/MacOS/prismlauncher"
codesign --sign - --deep --force \
  --entitlements ../program_info/AdhocSignedApp.entitlements --options runtime \
  "PrismLauncher.app/Contents/MacOS/prismlauncher"
mv "PrismLauncher.app" "Prism Launcher.app"
# This copy was built here, not downloaded, so it carries no quarantine flag; clear it anyway.
xattr -dr com.apple.quarantine "Prism Launcher.app" 2>/dev/null || true

echo
echo "Done: $PWD/Prism Launcher.app"
echo "Drag it to /Applications, then open Settings > APIs > Relay Server."
