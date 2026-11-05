#!/bin/bash
# Installs Rampart from a built app (default dist/Rampart.app) without the .pkg.
#   sudo scripts/install.sh [path/to/Rampart.app]      real install (asks nothing else)
#   scripts/install.sh --dry-run [path]                print every action, change nothing
# Copies the app to /Applications, then runs Contents/Resources/rampart-setup.sh install (helper binary
# in /Library/PrivilegedHelperTools, LaunchDaemon + LaunchAgent, /usr/local/bin/rampart symlink).
set -euo pipefail
cd "$(dirname "$0")/.."
DRY=""; SRC=""
for a in "$@"; do case "$a" in --dry-run) DRY="--dry-run" ;; *) SRC="$a" ;; esac; done
SRC="${SRC:-dist/Rampart.app}"
[ -d "$SRC" ] || { echo "install.sh: $SRC not found; run scripts/build.sh first" >&2; exit 66; }
codesign --verify --strict "$SRC" || { echo "install.sh: $SRC fails codesign verification" >&2; exit 65; }
if [ -z "$DRY" ] && [ "$(id -u)" != 0 ]; then echo "install.sh: run with sudo (or use --dry-run)" >&2; exit 77; fi

DEST=/Applications/Rampart.app
if [ -n "$DRY" ]; then
  echo "[dry-run] launchctl bootout system/app.rampart.daemon"
  echo "[dry-run] rm -rf $DEST && ditto $SRC $DEST && chown -R root:wheel $DEST"
  RAMPART_APP="$SRC" bash Packaging/rampart-setup.sh install --dry-run
  exit 0
fi
launchctl bootout system/app.rampart.daemon 2>/dev/null || true
rm -rf "$DEST"
ditto "$SRC" "$DEST"
chown -R root:wheel "$DEST"
xattr -dr com.apple.quarantine "$DEST" 2>/dev/null || true
RAMPART_APP="$DEST" bash "$DEST/Contents/Resources/rampart-setup.sh" install
echo "Done. Check with: rampart status"
