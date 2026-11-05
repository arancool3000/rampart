#!/bin/bash
# Removes every trace of Rampart and verifies nothing is left (exit 1 lists leftovers).
#   sudo scripts/uninstall.sh [--keep-data]     real uninstall (--keep-data keeps quarantine/history)
#   scripts/uninstall.sh --dry-run              print every action, change nothing
#   scripts/uninstall.sh --verify               only check for leftovers
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SETUP="$HERE/Packaging/rampart-setup.sh"
[ -f "$SETUP" ] || SETUP="/Applications/Rampart.app/Contents/Resources/rampart-setup.sh"
[ -f "$SETUP" ] || { echo "uninstall.sh: rampart-setup.sh not found" >&2; exit 66; }
if [ "${1:-}" = "--verify" ]; then exec bash "$SETUP" verify-removed; fi
exec bash "$SETUP" uninstall "$@"
