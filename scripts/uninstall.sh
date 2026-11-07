#!/bin/bash
# Removes every trace of Rampart and verifies nothing is left (exit 1 lists leftovers).
#   sudo scripts/uninstall.sh [--keep-data]     real uninstall (--keep-data keeps quarantine/history)
#   scripts/uninstall.sh --dry-run              print every action, change nothing
#   scripts/uninstall.sh --verify               only check for leftovers
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SETUP="$HERE/Packaging/rampart-setup.sh"
if [ ! -f "$SETUP" ]; then
  # Fallback: the installed copy. /Applications is admin-writable, so under sudo run it only if it is a
  # root-owned file nobody else can write, read through one descriptor (no swap between check and run).
  SETUP="/Applications/Rampart.app/Contents/Resources/rampart-setup.sh"
  [ -f "$SETUP" ] && [ ! -L "$SETUP" ] || { echo "uninstall.sh: rampart-setup.sh not found" >&2; exit 66; }
  exec 3<"$SETUP"
  if [ "$(id -u)" = 0 ] && { [ "$(stat -f '%u:%i' /dev/fd/3)" != "0:$(stat -f %i "$SETUP")" ] || [ $(( 0$(stat -f %Lp "$SETUP") & 022 )) != 0 ]; }; then
    echo "uninstall.sh: $SETUP is not root-owned; run this script from the source checkout instead" >&2; exit 65
  fi
  SETUP=/dev/fd/3
fi
if [ "${1:-}" = "--verify" ]; then exec /bin/bash "$SETUP" verify-removed; fi
exec /bin/bash "$SETUP" uninstall "$@"
