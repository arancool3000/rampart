#!/bin/sh
# RamPart Super Kill Switch (path B): turns off everything RamPart does to the network and gets the Mac back online,
# using only plain macOS tools. It never runs a RamPart binary, so it works when the service is hung, dead,
# crash-looping or mismatched. The app runs it from inside its own signed bundle through the macOS administrator
# prompt; `sudo sh killswitch.sh` works too.
#
# Every step is independent: a failing step is reported and the next one still runs.
#
# Dry run (prints every command, changes nothing): --dry-run, RAMPART_KILLSWITCH_DRY_RUN=1, or
# RAMPART_NO_PRIVILEGED_TOOLS=1 (always on in tests). Test fixtures for the listings:
#   RAMPART_KS_ANCHORS   output of `pfctl -s Anchors` + `pfctl -a com.apple -s Anchors` to use instead of pfctl
#   RAMPART_KS_SERVICES  output of `networksetup -listallnetworkservices` to use instead of networksetup
#   RAMPART_KS_ROOT      RamPart state folder (default /Library/Application Support/Rampart)

# wms-fc: unset variables are errors, the environment can't redirect a real run (fixtures count only in dry runs),
# listings are never glob-expanded, and dyld/shell injection variables are dropped.
set -u
set -f
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
unset BASH_ENV ENV CDPATH IFS DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH 2>/dev/null || true
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1
[ "${RAMPART_KILLSWITCH_DRY_RUN:-0}" = "1" ] && DRY=1
[ -n "${RAMPART_NO_PRIVILEGED_TOOLS:-}" ] && [ "${RAMPART_NO_PRIVILEGED_TOOLS}" != "0" ] && DRY=1
ROOT="/Library/Application Support/Rampart"
if [ "$DRY" = "1" ]; then
  ROOT="${RAMPART_KS_ROOT:-$ROOT}"
else
  unset RAMPART_KS_ANCHORS RAMPART_KS_SERVICES RAMPART_KS_ROOT 2>/dev/null || true
fi
OK=0; FAILED=0

run() {
  if [ "$DRY" = "1" ]; then echo "DRY-RUN: $*"; return 0; fi
  "$@" >/dev/null 2>&1
}
step() {  # step <title> <status>
  if [ "$2" = "0" ]; then echo "OK: $1"; OK=$((OK + 1)); else echo "FAILED: $1"; FAILED=$((FAILED + 1)); fi
}

# 1. Lift any emergency lockdown: set its state aside so a restarted service doesn't re-apply it.
rc=0
if [ -f "$ROOT/emergency.json" ] && [ ! -L "$ROOT/emergency.json" ]; then
  PIDS=$(head -c 1048576 "$ROOT/emergency.json" 2>/dev/null | tr -d ' \n' | grep -o '"pids":\[[0-9,]*\]' | tr -cs '0-9' ' ')
  run mv -f "$ROOT/emergency.json" "$ROOT/emergency.json.killswitch" || rc=1
else
  PIDS=""
fi
step "lift emergency lockdown" $rc

# 2. Unload every RamPart pf anchor (known ones plus anything listed with Rampart in its name).
rc=0
KNOWN="com.apple/249.RampartEmergency com.apple/250.Rampart com.apple/251.RampartRemote app.rampart/lure"
[ "$DRY" = "1" ] || [ -x /sbin/pfctl ] || rc=1
if [ -n "${RAMPART_KS_ANCHORS+x}" ]; then
  LISTED="$RAMPART_KS_ANCHORS"
elif [ "$DRY" = "1" ]; then
  LISTED=""
else
  LISTED="$(pfctl -s Anchors 2>/dev/null; pfctl -a com.apple -s Anchors 2>/dev/null)"
fi
FOUND=$(printf '%s\n' "$LISTED" | tr -d ' \t' | grep -i 'rampart')
for a in $(printf '%s\n' $KNOWN $FOUND | sort -u); do
  case "$a" in *[!A-Za-z0-9._/-]*|"") echo "  (skipping anchor with unexpected characters: $a)"; continue ;; esac
  run pfctl -a "$a" -F all || echo "  (nothing loaded in $a)"
done
step "unload RamPart firewall rules" $rc

# 3. DNS back to automatic on every network service.
rc=0
if [ -n "${RAMPART_KS_SERVICES+x}" ]; then
  SERVICES="$RAMPART_KS_SERVICES"
else
  SERVICES="$(networksetup -listallnetworkservices 2>/dev/null)"
fi
printf '%s\n' "$SERVICES" | sed '1{/asterisk/d;}' | sed 's/^\*//' | while IFS= read -r svc; do
  [ -z "$svc" ] && continue
  run networksetup -setdnsservers "$svc" Empty || echo "  (could not reset DNS for $svc)"
done
run dscacheutil -flushcache || rc=1
run killall -HUP mDNSResponder || true
step "restore automatic DNS" $rc

# 4. Resume every process RamPart froze.
rc=0
for pid in $PIDS; do [ "$pid" -gt 1 ] 2>/dev/null && { run kill -CONT "$pid" || true; }; done
step "resume frozen processes" $rc

# 5. Stop the service (DNS filter, network lure, web protection, remote-access lockdown, Wi-Fi guard all live in it).
rc=0
for l in app.rampart.sentinel app.rampart.watchdog app.rampart.daemon; do
  run launchctl bootout "system/$l" || true
done
step "stop the RamPart service (web protection, lure, remote-access lockdown, Wi-Fi guard)" $rc

# 6. Real-time protection stays paused: the service is stopped until you turn RamPart back on (or restart the Mac).
step "pause real-time protection" 0

echo "DONE: $OK ok, $FAILED failed. You should be back online."
exit 0
