#!/bin/bash
# Installs Rampart from a built app (default dist/RamPart.app, falling back to dist/Rampart.app) without the .pkg.
#   sudo scripts/install.sh [--allow-downgrade] [path/to/Rampart.app]    real install
#   scripts/install.sh --dry-run [path]                                  print every action, change nothing
# Runs Packaging/rampart-setup.sh install-from: pins the source's cdhash, copies it into a root-only staging
# folder, verifies the COPY (strict codesign + same cdhash, so editing the source mid-copy can't change what
# root runs), refuses a downgrade or a different signer, swaps it into /Applications, then installs the helper
# binary (/Library/PrivilegedHelperTools), the LaunchDaemon + LaunchAgent and the /usr/local/bin/rampart link.
# wms-fc: fixed PATH, absolute paths, and the root script starts under `env -i` so nothing from this shell's
# environment (BASH_ENV, DYLD_*, IFS, PATH, RAMPART_DAEMON_SRC...) reaches the code that runs as root.
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH
cd "$(dirname "$0")/.."
HERE="$(pwd -P)"
FLAGS=(); SRC=""
for a in "$@"; do case "$a" in --dry-run|--allow-downgrade) FLAGS+=("$a") ;; -*) echo "install.sh: unknown option $a" >&2; exit 64 ;; *) SRC="$a" ;; esac; done
if [ -z "$SRC" ]; then SRC=dist/RamPart.app; [ -d "$SRC" ] || SRC=dist/Rampart.app; fi
[ -d "$SRC" ] || { echo "install.sh: $SRC not found; run scripts/build.sh first" >&2; exit 66; }
SRC="$(cd "$SRC" && pwd -P)"
/usr/bin/codesign --verify --strict --deep "$SRC" || { echo "install.sh: $SRC fails codesign verification" >&2; exit 65; }
DRY=0; for f in "${FLAGS[@]+"${FLAGS[@]}"}"; do [ "$f" = --dry-run ] && DRY=1; done
if [ "$DRY" = 0 ] && [ "$(id -u)" != 0 ]; then echo "install.sh: run with sudo (or use --dry-run)" >&2; exit 77; fi
# Dry runs keep the test fixture variables (honoured by rampart-setup.sh only with --dry-run).
KEEP=()
if [ "$DRY" = 1 ]; then for k in RAMPART_TEST_USERS_DIR RAMPART_TEST_IDENTITY RAMPART_TEST_PF_ANCHORS; do [ -n "${!k:-}" ] && KEEP+=("$k=${!k}"); done; fi
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin "${KEEP[@]+"${KEEP[@]}"}" /bin/bash "$HERE/Packaging/rampart-setup.sh" install-from "$SRC" /Applications/Rampart.app "${FLAGS[@]+"${FLAGS[@]}"}"
