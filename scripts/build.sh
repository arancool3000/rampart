#!/bin/bash
# Rampart: release build -> Rampart.app (app + embedded rampartd + rampart CLI) -> sign -> DMG -> PKG.
# Command Line Tools only. Never installs anything.
#   scripts/build.sh                 everything
#   SKIP_DMG=1 SKIP_PKG=1 scripts/build.sh
#   SIGN_ID="Rampart Local Signing" scripts/build.sh   (default: that identity if present, else ad-hoc)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

APP_NAME="Rampart"            # bundle/file name (paths stay lowercase-safe)
DISPLAY_NAME="${DISPLAY_NAME:-$(sed -n 's/.*static let name = "\(.*\)".*/\1/p' Sources/RampartShared/Models.swift | head -1)}"
DISPLAY_NAME="${DISPLAY_NAME:-RamPart}"
# Bundle folder uses the display name (dist/RamPart.app); the executable inside stays "Rampart".
# APFS is case-insensitive, so /Applications/RamPart.app and /Applications/Rampart.app are the same path.
BUNDLE_ID="app.rampart.app"
VERSION="${VERSION:-$(sed -n 's/.*static let version = "\(.*\)".*/\1/p' Sources/RampartShared/Models.swift | head -1)}"
VERSION="${VERSION:-0.1.0}"
BUILD="${BUILD:-$(date +%Y%m%d%H%M)}"
CONFIG="${CONFIG:-release}"
SCRATCH="${SCRATCH:-.build-release}"
DIST="${DIST:-dist}"
APP="$DIST/$DISPLAY_NAME.app"
STABLE_ID_NAME="${STABLE_ID_NAME:-Rampart Local Signing}"

if [ -z "${SIGN_ID:-}" ]; then
  if security find-identity -p codesigning 2>/dev/null | grep -q "\"$STABLE_ID_NAME\""; then SIGN_ID="$STABLE_ID_NAME"; else SIGN_ID="-"; fi
fi

echo "==> swift build ($CONFIG, scratch $SCRATCH) v$VERSION ($BUILD)"
PRODUCTS="rampartd rampart RampartApp"
grep -q '"rampart-nmh"' Package.swift && PRODUCTS="$PRODUCTS rampart-nmh"
for p in $PRODUCTS; do
  LOGF="$(mktemp -t rampart-build)"
  if ! swift build -c "$CONFIG" --scratch-path "$SCRATCH" --product "$p" >"$LOGF" 2>&1; then
    grep -E "error|warning: unre" "$LOGF" | head -40 >&2; rm -f "$LOGF"; echo "build of $p failed" >&2; exit 1
  fi
  grep -E "Build complete|Compiling" "$LOGF" | tail -1; rm -f "$LOGF"
done
BIN="$(swift build -c "$CONFIG" --scratch-path "$SCRATCH" --show-bin-path)"
for p in $PRODUCTS; do [ -x "$BIN/$p" ] || { echo "missing $BIN/$p" >&2; exit 1; }; done

echo "==> assemble $APP"
rm -rf "$APP"
# The CLI goes in Contents/Helpers: "rampart" and "Rampart" are the same name on case-insensitive APFS.
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Helpers" "$APP/Contents/Resources" "$APP/Contents/Library/LaunchDaemons" "$APP/Contents/Library/LaunchAgents"
cp "$BIN/RampartApp" "$APP/Contents/MacOS/$APP_NAME"
cp "$BIN/rampartd"   "$APP/Contents/MacOS/rampartd"      # root LaunchDaemon source (copied to PrivilegedHelperTools)
cp "$BIN/rampartd"   "$APP/Contents/Helpers/rampartd"    # --user LaunchAgent (app.rampart.userdaemon)
[ -x "$BIN/rampart-nmh" ] && cp "$BIN/rampart-nmh" "$APP/Contents/Helpers/rampart-nmh"
cp "$BIN/rampart"    "$APP/Contents/Helpers/rampart"
sed -e "s/__VERSION__/$VERSION/" -e "s/__BUILD__/$BUILD/" -e "s/__DISPLAY_NAME__/$DISPLAY_NAME/g" Packaging/Info.plist > "$APP/Contents/Info.plist"
printf 'APPL????' > "$APP/Contents/PkgInfo"
# SMAppService variants (BundleProgram) inside the bundle; system-install variants in Resources for rampart-setup.sh.
cp Packaging/bundle/app.rampart.daemon.plist "$APP/Contents/Library/LaunchDaemons/"
cp Packaging/bundle/app.rampart.agent.plist  "$APP/Contents/Library/LaunchAgents/"
cp Packaging/app.rampart.userdaemon.plist    "$APP/Contents/Library/LaunchAgents/"
# Browser extension sources (unpacked; loaded by the user from Settings) for the native messaging host.
[ -d Extensions ] && [ -n "$(ls -A Extensions 2>/dev/null)" ] && cp -RL Extensions "$APP/Contents/Resources/Extensions"
cp Packaging/app.rampart.daemon.plist Packaging/app.rampart.agent.plist "$APP/Contents/Resources/"
install -m 755 Packaging/rampart-setup.sh "$APP/Contents/Resources/rampart-setup.sh"
[ -d Rules ] && [ -n "$(ls -A Rules 2>/dev/null)" ] && cp -RL Rules "$APP/Contents/Resources/Rules"
for b in "$BIN"/*.bundle; do [ -e "$b" ] && cp -R "$b" "$APP/Contents/Resources/"; done
plutil -lint "$APP/Contents/Info.plist" >/dev/null

echo "==> icon"
if [ -f Resources/Brand/AppIcon.icns ]; then
  cp Resources/Brand/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
  for f in Resources/Brand/*.png Resources/Brand/*.pdf Resources/Brand/*.svg; do [ -e "$f" ] && cp "$f" "$APP/Contents/Resources/"; done
else
ICON_SRC="${ICON_SRC:-Packaging/AppIcon-1024.png}"
[ -f "$ICON_SRC" ] || swift Packaging/make-icon-png.swift "$ICON_SRC"
ICONSET="$DIST/AppIcon.iconset"; rm -rf "$ICONSET"; mkdir -p "$ICONSET"
for s in 16 32 128 256 512; do
  sips -z $s $s             "$ICON_SRC" --out "$ICONSET/icon_${s}x${s}.png"    >/dev/null
  sips -z $((s*2)) $((s*2)) "$ICON_SRC" --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
rm -rf "$ICONSET"
fi

echo "==> codesign (${SIGN_ID/#-/ad-hoc})"
# Inside-out; explicit identifiers keep TCC/FDA grants stable with a stable identity.
codesign --force --options runtime --timestamp=none -s "$SIGN_ID" --identifier app.rampart.daemon "$APP/Contents/MacOS/rampartd"
codesign --force --options runtime --timestamp=none -s "$SIGN_ID" --identifier app.rampart.daemon "$APP/Contents/Helpers/rampartd"
codesign --force --options runtime --timestamp=none -s "$SIGN_ID" --identifier app.rampart.cli    "$APP/Contents/Helpers/rampart"
[ -x "$APP/Contents/Helpers/rampart-nmh" ] && codesign --force --options runtime --timestamp=none -s "$SIGN_ID" --identifier app.rampart.nmh "$APP/Contents/Helpers/rampart-nmh"
codesign --force --options runtime --timestamp=none -s "$SIGN_ID" --entitlements Packaging/Rampart.entitlements "$APP"
codesign --verify --strict --verbose=1 "$APP"
"$APP/Contents/MacOS/rampartd" --version
"$APP/Contents/Helpers/rampart" version
# Never launch the GUI here; just make sure the bundle's main executable is the app, not a helper.
[ "$(stat -f %z "$APP/Contents/MacOS/$APP_NAME")" != "$(stat -f %z "$APP/Contents/Helpers/rampart")" ] || { echo "app executable clobbered" >&2; exit 1; }

if [ -z "${SKIP_DMG:-}" ]; then
  echo "==> DMG"
  STAGE="$DIST/dmg-stage"; rm -rf "$STAGE" "$DIST/$APP_NAME.dmg"; mkdir -p "$STAGE"
  cp -R "$APP" "$STAGE/"
  ln -s /Applications "$STAGE/Applications"
  if diskutil image create from --help >/dev/null 2>&1; then
    diskutil image create from --format UDZO --volumeName "$DISPLAY_NAME" "$STAGE" "$DIST/$APP_NAME.dmg" >/dev/null 2>&1
  else
    hdiutil create -volname "$DISPLAY_NAME" -srcfolder "$STAGE" -ov -format UDZO "$DIST/$APP_NAME.dmg" >/dev/null 2>&1
  fi
  rm -rf "$STAGE"
  codesign --force -s "$SIGN_ID" "$DIST/$APP_NAME.dmg"
  hdiutil verify "$DIST/$APP_NAME.dmg" >/dev/null 2>&1 && echo "dmg ok: $DIST/$APP_NAME.dmg"
fi

if [ -z "${SKIP_PKG:-}" ]; then
  echo "==> PKG"
  PKGROOT="$DIST/pkgroot"; rm -rf "$PKGROOT"; mkdir -p "$PKGROOT/Applications"
  cp -R "$APP" "$PKGROOT/Applications/"
  pkgbuild --analyze --root "$PKGROOT" "$DIST/components.plist" >/dev/null
  /usr/libexec/PlistBuddy -c "Add :0:BundleIsRelocatable bool false" "$DIST/components.plist"
  pkgbuild --root "$PKGROOT" --component-plist "$DIST/components.plist" \
    --identifier "$BUNDLE_ID.pkg" --version "$VERSION" --install-location / \
    --scripts Packaging/scripts "$DIST/$APP_NAME-component.pkg" 2>&1 | grep -v "Permission denied" || true
  productbuild --package "$DIST/$APP_NAME-component.pkg" "$DIST/$APP_NAME.pkg" 2>&1 | grep -v "Permission denied" || true
  rm -rf "$PKGROOT" "$DIST/components.plist" "$DIST/$APP_NAME-component.pkg"
  pkgutil --payload-files "$DIST/$APP_NAME.pkg" > "$DIST/pkg-files.txt"
  echo "pkg ok: $DIST/$APP_NAME.pkg ($(wc -l < "$DIST/pkg-files.txt" | tr -d ' ') payload entries)"
fi

echo "==> done: $APP${SKIP_DMG:+}  $( [ -z "${SKIP_DMG:-}" ] && echo "$DIST/$APP_NAME.dmg")  $( [ -z "${SKIP_PKG:-}" ] && echo "$DIST/$APP_NAME.pkg")"
