#!/bin/bash
# Rampart system setup: install | uninstall | verify  [--dry-run] [--keep-data]
# Shipped inside Rampart.app/Contents/Resources and used by the .pkg postinstall, scripts/install.sh and
# scripts/uninstall.sh. install/uninstall need root. --dry-run prints every action without doing it.
set -uo pipefail

ACTION="${1:-}"; shift || true
DRY=0; KEEP_DATA=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --keep-data) KEEP_DATA=1 ;;
    *) echo "unknown option $a" >&2; exit 64 ;;
  esac
done

APP="${RAMPART_APP:-/Applications/Rampart.app}"
LABEL_D="app.rampart.daemon"
LABEL_A="app.rampart.agent"
HELPER="/Library/PrivilegedHelperTools/app.rampart.daemon"
DAEMON_PLIST="/Library/LaunchDaemons/$LABEL_D.plist"
AGENT_PLIST="/Library/LaunchAgents/$LABEL_A.plist"
SUPPORT="/Library/Application Support/Rampart"
LOGS="/Library/Logs/Rampart"
SOCKET="/var/run/rampart.sock"
CLI_LINK="/usr/local/bin/rampart"
PKG_ID="app.rampart.app.pkg"
BUNDLE_ID="app.rampart.app"

run() {
  if [ "$DRY" = 1 ]; then printf '[dry-run]'; printf ' %q' "$@"; printf '\n'; return 0; fi
  "$@"
}
need_root() {
  if [ "$DRY" = 0 ] && [ "$(id -u)" != 0 ]; then echo "rampart-setup: $ACTION needs root (use sudo)" >&2; exit 77; fi
}
console_uid() { stat -f %u /dev/console 2>/dev/null || echo 0; }

install_rampart() {
  need_root
  [ -d "$APP" ] || { echo "rampart-setup: $APP not found" >&2; exit 66; }
  [ -x "$APP/Contents/MacOS/rampartd" ] || { echo "rampart-setup: $APP has no rampartd" >&2; exit 66; }
  local res="$APP/Contents/Resources"
  echo "==> Installing the Rampart protection service"
  # Upgrade: stop the old service first.
  run launchctl bootout "system/$LABEL_D" 2>/dev/null || true
  run install -d -o root -g wheel -m 755 /Library/PrivilegedHelperTools
  run install -o root -g wheel -m 755 "$APP/Contents/MacOS/rampartd" "$HELPER"
  run install -d -o root -g wheel -m 755 "$SUPPORT" "$LOGS"
  run install -o root -g wheel -m 644 "$res/$LABEL_D.plist" "$DAEMON_PLIST"
  run install -o root -g wheel -m 644 "$res/$LABEL_A.plist" "$AGENT_PLIST"
  run launchctl bootstrap system "$DAEMON_PLIST"
  run launchctl enable "system/$LABEL_D"
  # Command line tool.
  run install -d -m 755 /usr/local/bin
  run ln -sfn "$APP/Contents/Helpers/rampart" "$CLI_LINK"
  # Start the menu bar agent for the logged-in user (the agent plist also loads at every login).
  local uid; uid="$(console_uid)"
  if [ "$uid" != 0 ]; then
    # The root daemon replaces the no-root user daemon.
    run launchctl bootout "gui/$uid/app.rampart.userdaemon" 2>/dev/null || true
    run launchctl bootout "gui/$uid/$LABEL_A" 2>/dev/null || true
    run launchctl bootstrap "gui/$uid" "$AGENT_PLIST" || true
  fi
  echo "==> Installed. Grant Full Disk Access to $HELPER in"
  echo "    System Settings > Privacy & Security > Full Disk Access, for real-time protection (eslogger)."
}

restore_dns() {
  # rampartd restores DNS itself on SIGTERM; this is the fallback if it was killed.
  local snap="$SUPPORT/dns-original.json"
  [ -f "$snap" ] || return 0
  echo "==> Restoring DNS settings from $snap"
  local n i svc servers
  n=$(plutil -extract services raw -o - "$snap" 2>/dev/null || echo 0)
  for ((i = 0; i < n; i++)); do
    svc=$(plutil -extract "services.$i.service" raw -o - "$snap" 2>/dev/null) || continue
    servers=()
    local m j
    m=$(plutil -extract "services.$i.servers" raw -o - "$snap" 2>/dev/null || echo 0)
    for ((j = 0; j < m; j++)); do servers+=("$(plutil -extract "services.$i.servers.$j" raw -o - "$snap")"); done
    if [ "${#servers[@]}" = 0 ]; then run networksetup -setdnsservers "$svc" empty
    else run networksetup -setdnsservers "$svc" "${servers[@]}"; fi
  done
  run dscacheutil -flushcache; run killall -HUP mDNSResponder 2>/dev/null || true
}

uninstall_rampart() {
  need_root
  echo "==> Stopping Rampart"
  run launchctl bootout "system/$LABEL_D" 2>/dev/null || true
  for home in /Users/*; do
    local uid; uid=$(stat -f %u "$home" 2>/dev/null) || continue
    [ "$uid" -ge 500 ] 2>/dev/null || continue
    run launchctl bootout "gui/$uid/$LABEL_A" 2>/dev/null || true
    run launchctl bootout "gui/$uid/app.rampart.userdaemon" 2>/dev/null || true
  done
  run pkill -x rampartd 2>/dev/null || true
  run pkill -f "$HELPER" 2>/dev/null || true
  run pkill -x Rampart 2>/dev/null || true
  restore_dns
  # pf anchor (only ever loaded under com.apple/250.Rampart; never in pf.conf).
  run pfctl -a com.apple/250.Rampart -F all 2>/dev/null || true

  echo "==> Removing files"
  run rm -f "$DAEMON_PLIST" "$AGENT_PLIST" "$HELPER" "$SOCKET"
  if [ -L "$CLI_LINK" ] && readlink "$CLI_LINK" | grep -qi "Rampart.app"; then run rm -f "$CLI_LINK"; fi
  run rm -rf "$APP" "$LOGS"
  if [ "$KEEP_DATA" = 0 ]; then run rm -rf "$SUPPORT"; else echo "    keeping $SUPPORT (--keep-data)"; fi
  for home in /Users/*; do
    [ -d "$home/Library" ] || continue
    if [ "$KEEP_DATA" = 0 ]; then run rm -rf "$home/Library/Application Support/Rampart"; fi
    run rm -f "$home/Library/LaunchAgents/$LABEL_A.plist" "$home/Library/LaunchAgents/$BUNDLE_ID.plist"
    run rm -rf "$home/Library/Caches/$BUNDLE_ID" "$home/Library/HTTPStorages/$BUNDLE_ID" \
               "$home/Library/Saved Application State/$BUNDLE_ID.savedState"
    run rm -f "$home/Library/Preferences/$BUNDLE_ID.plist"
  done
  run pkgutil --forget "$PKG_ID" 2>/dev/null || true
  run tccutil reset All "$BUNDLE_ID" 2>/dev/null || true
  if [ "$DRY" = 0 ]; then verify_removed; else echo "[dry-run] would verify nothing is left"; fi
}

# Exit 0 only if no trace of Rampart remains.
verify_removed() {
  local left=()
  local paths=("$DAEMON_PLIST" "$AGENT_PLIST" "$HELPER" "$SOCKET" "$APP" "$LOGS")
  [ "$KEEP_DATA" = 0 ] && paths+=("$SUPPORT")
  for p in "${paths[@]}"; do [ -e "$p" ] || [ -L "$p" ] && left+=("$p"); done
  if [ -L "$CLI_LINK" ] && readlink "$CLI_LINK" | grep -qi "Rampart.app"; then left+=("$CLI_LINK"); fi
  for home in /Users/*; do
    for p in "$home/Library/LaunchAgents/$LABEL_A.plist" "$home/Library/Preferences/$BUNDLE_ID.plist"; do
      [ -e "$p" ] && left+=("$p")
    done
    [ "$KEEP_DATA" = 0 ] && [ -e "$home/Library/Application Support/Rampart" ] && left+=("$home/Library/Application Support/Rampart")
  done
  launchctl print "system/$LABEL_D" >/dev/null 2>&1 && left+=("launchd job system/$LABEL_D")
  pgrep -x rampartd >/dev/null 2>&1 && left+=("running rampartd process")
  pgrep -f "$HELPER" >/dev/null 2>&1 && left+=("running $HELPER process")
  pkgutil --pkgs 2>/dev/null | grep -q "^$PKG_ID\$" && left+=("pkg receipt $PKG_ID")
  if [ "${#left[@]}" = 0 ]; then
    echo "==> Verified: Rampart is completely removed."
    return 0
  fi
  echo "==> Uninstall incomplete; still present:" >&2
  printf '    %s\n' "${left[@]}" >&2
  return 1
}

verify_installed() {
  local ok=0
  for p in "$HELPER" "$DAEMON_PLIST" "$AGENT_PLIST" "$APP"; do
    if [ -e "$p" ]; then echo "ok    $p"; else echo "MISSING $p"; ok=1; fi
  done
  if launchctl print "system/$LABEL_D" >/dev/null 2>&1; then echo "ok    launchd job system/$LABEL_D"
  else echo "MISSING launchd job system/$LABEL_D (needs root to see)"; ok=1; fi
  [ -S "$SOCKET" ] && echo "ok    $SOCKET" || { echo "MISSING $SOCKET"; ok=1; }
  return $ok
}

case "$ACTION" in
  install) install_rampart ;;
  uninstall) uninstall_rampart ;;
  verify) verify_installed ;;
  verify-removed) verify_removed ;;
  *) echo "usage: rampart-setup.sh install|uninstall|verify|verify-removed [--dry-run] [--keep-data]" >&2; exit 64 ;;
esac
