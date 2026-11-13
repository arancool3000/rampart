#!/bin/bash
# Removes every trace of Rampart and verifies nothing is left (exit 1 lists leftovers).
#   sudo scripts/uninstall.sh [--keep-data]     real uninstall (--keep-data keeps quarantine/history)
#   scripts/uninstall.sh --dry-run              print every action, change nothing
#   scripts/uninstall.sh --verify               only check for leftovers
# wms-fc: fixed PATH; the root script starts under `env -i` (see install.sh).
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH
HERE="$(cd "$(dirname "$0")/.." && pwd -P)"
CLEAN=(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin)
for k in RAMPART_TEST_USERS_DIR RAMPART_TEST_IDENTITY RAMPART_TEST_PF_ANCHORS; do [ -n "${!k:-}" ] && CLEAN+=("$k=${!k}"); done
SETUP="$HERE/Packaging/rampart-setup.sh"
if [ ! -f "$SETUP" ]; then
  # Fallback: the installed copy. /Applications is admin-writable, so under sudo run it only if it is a
  # root-owned file nobody else can write, read through one descriptor (no swap between check and run).
  SETUP="/Applications/Rampart.app/Contents/Resources/rampart-setup.sh"
  [ -f "$SETUP" ] && [ ! -L "$SETUP" ] || { echo "uninstall.sh: rampart-setup.sh not found" >&2; exit 66; }
  exec 3<"$SETUP"
  if [ "$(id -u)" = 0 ] && { [ "$(/usr/bin/stat -f '%u:%i' /dev/fd/3)" != "0:$(/usr/bin/stat -f %i "$SETUP")" ] || [ $(( 0$(/usr/bin/stat -f %Lp "$SETUP") & 022 )) != 0 ]; }; then
    echo "uninstall.sh: $SETUP is not root-owned; run this script from the source checkout instead" >&2; exit 65
  fi
  SETUP=/dev/fd/3
fi
if [ "${1:-}" = "--verify" ]; then exec "${CLEAN[@]}" /bin/bash "$SETUP" verify-removed; fi
exec "${CLEAN[@]}" /bin/bash "$SETUP" uninstall "$@"
