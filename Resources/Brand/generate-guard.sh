#!/bin/zsh
# Regenerates the RamPart Pixel Guard assets (offscreen, CoreGraphics only):
#   Resources/Brand/generate-guard.sh                 → AppIcon.iconset + AppIcon.icns, logo-mark-1024.png,
#                                                       MenuBarIconTemplate(@2x).png, previews/icon-*.png
#   Resources/Brand/generate-guard.sh --previews DIR  → variant sheets + bot pose sheet into DIR only
# The pixel matrix and palette live in ONE place: Sources/RampartApp/Features/Bot/PixelGuard.swift.
set -e
cd "$(dirname "$0")/../.."
OUT="${TMPDIR:-/tmp}/rampart-generate-guard"
mkdir -p "$OUT"
swiftc -O -parse-as-library -module-name GenerateGuard \
  Sources/RampartApp/Features/Bot/PixelGuard.swift \
  Sources/RampartApp/Features/Bot/BotLogic.swift \
  Resources/Brand/generate-guard.swift -o "$OUT/generate-guard"
"$OUT/generate-guard" "$@"
if [ "$1" != "--previews" ]; then
  iconutil -c icns Resources/Brand/AppIcon.iconset -o Resources/Brand/AppIcon.icns
  echo "wrote AppIcon.icns"
fi
