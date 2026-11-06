#!/bin/bash
# Builds RamPartSafari.appex without Xcode, using swiftc from the Command Line Tools.
#
#   Extensions/safari/build-appex.sh [--out <dir>] [--sign <identity>] [--app <RamPart.app>]
#
# Output: <out>/RamPartSafari.appex (default: dist/RamPartSafari.appex). With --app, the appex is
# copied into <RamPart.app>/Contents/PlugIns/ so scripts/build.sh can call this before signing the app.
# The appex MUST be signed before the enclosing app; nested code is sealed by the outer signature.
#
# Preferred path: once Package.swift has the `rampart-safari-ext` executable target (see README),
# this script uses `swift build --product rampart-safari-ext`. Otherwise it compiles the three
# modules directly with swiftc (slower, same result).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/dist"; SIGN="-"; APP=""
while [ $# -gt 0 ]; do case "$1" in
  --out) OUT="$2"; shift 2;; --sign) SIGN="$2"; shift 2;; --app) APP="$2"; shift 2;; *) echo "unknown arg $1"; exit 2;; esac; done
VERSION=$(grep -o 'version = "[^"]*"' "$ROOT/Sources/RampartShared/Models.swift" | head -1 | cut -d'"' -f2)
BUILD=$(date +%Y%m%d%H%M)
SCRATCH="$ROOT/.build-safari"
mkdir -p "$SCRATCH/obj" "$OUT"
APPEX="$OUT/RamPartSafari.appex"
rm -rf "$APPEX"; mkdir -p "$APPEX/Contents/MacOS" "$APPEX/Contents/Resources"

echo "==> compile"
if grep -q 'name: "rampart-safari-ext"' "$ROOT/Package.swift"; then
  (cd "$ROOT" && swift build -c release --scratch-path "$SCRATCH" --product rampart-safari-ext)
  BIN=$(find "$SCRATCH" -type f -perm +111 -name rampart-safari-ext | head -1)
  cp "$BIN" "$APPEX/Contents/MacOS/RamPartSafari"
else
  SDK=$(xcrun --show-sdk-path)
  FLAGS=(-O -sdk "$SDK" -target arm64-apple-macosx14.0 -swift-version 5 -I "$SCRATCH/obj")
  swiftc "${FLAGS[@]}" -parse-as-library -wmo -emit-module -module-name RampartShared -emit-module-path "$SCRATCH/obj/RampartShared.swiftmodule" -c -o "$SCRATCH/obj/RampartShared.o" "$ROOT"/Sources/RampartShared/*.swift
  swiftc "${FLAGS[@]}" -parse-as-library -wmo -emit-module -module-name RampartWeb -emit-module-path "$SCRATCH/obj/RampartWeb.swiftmodule" -c -o "$SCRATCH/obj/RampartWeb.o" "$ROOT"/Sources/RampartWeb/*.swift
  swiftc "${FLAGS[@]}" -wmo -module-name RamPartSafari -c -o "$SCRATCH/obj/RamPartSafari.o" "$ROOT"/Sources/RampartSafariExtension/*.swift
  swiftc -sdk "$SDK" -target arm64-apple-macosx14.0 -o "$APPEX/Contents/MacOS/RamPartSafari" "$SCRATCH"/obj/*.o -framework Foundation -framework SafariServices -Xlinker -rpath -Xlinker @executable_path/../Frameworks
fi

echo "==> resources (shared JS from Extensions/chromium + Safari manifest)"
SRC="$ROOT/Extensions/chromium"
cp -R "$SRC/shared" "$SRC/icons" "$APPEX/Contents/Resources/"
for f in background.js content.js content.css interstitial.html interstitial.css interstitial.js popup.html popup.js; do cp "$SRC/$f" "$APPEX/Contents/Resources/"; done
cp "$ROOT/Extensions/safari/manifest.json" "$APPEX/Contents/Resources/manifest.json"
cp -R "$ROOT/Extensions/safari/_locales" "$APPEX/Contents/Resources/"
sed -e "s/__VERSION__/$VERSION/" -e "s/__BUILD__/$BUILD/" "$ROOT/Extensions/safari/Info.plist.template" > "$APPEX/Contents/Info.plist"
plutil -lint "$APPEX/Contents/Info.plist"

echo "==> sign (${SIGN/#-/ad-hoc})"
codesign --force --options runtime --timestamp=none -s "$SIGN" --identifier app.rampart.safari \
  --entitlements "$ROOT/Extensions/safari/RamPartSafari.entitlements" "$APPEX"
codesign --verify --strict --verbose=1 "$APPEX"
echo "built $APPEX"

if [ -n "$APP" ]; then
  mkdir -p "$APP/Contents/PlugIns"
  rm -rf "$APP/Contents/PlugIns/RamPartSafari.appex"
  cp -R "$APPEX" "$APP/Contents/PlugIns/"
  echo "copied into $APP/Contents/PlugIns/ (re-sign the app afterwards)"
fi
