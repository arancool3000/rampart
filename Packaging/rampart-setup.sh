#!/bin/bash
# Rampart system setup. Every action needs root unless --dry-run (prints each action, changes nothing).
#   install                     install the root service from $RAMPART_APP (the .pkg postinstall path)
#   install-from SRC            stage SRC in a root-only folder, verify its signature, place it in
#                               /Applications and install the service (scripts/install.sh path)
#   place-staged STAGE DEST     DEST <- STAGE/Rampart.app (already staged and verified by root), then install
#   uninstall [--keep-data]     remove everything we installed, then verify nothing is left
#   verify | verify-removed
#   print-plist daemon|agent    print the LaunchDaemon / LaunchAgent plist this script installs
# Options: --dry-run --keep-data --allow-downgrade --expect-cdhash HEX
#
# Security model (docs/security/harden-hx7.md): code that ends up running as root is only ever taken from a
# root-only staging folder (mktemp -d as root, mode 700) or from a root-owned file opened once and checked
# through its descriptor. The bundle is verified AFTER the copy (pinned cdhash, strict codesign), so changing
# the source while it is being copied can't swap what root runs. Launchd plists are written from this script,
# never copied from the (admin-writable) app bundle. Uninstall only deletes our own fixed paths, checks bundle
# identity before deleting an app, and deletes per-user files as that user (no root symlink games).
#
# wms-fc: the script trusts nothing from its caller's environment. PATH is fixed, every variable that changes how bash
# or dyld behave (BASH_ENV, ENV, CDPATH, GLOBIGNORE, IFS, DYLD_*, LD_*) is cleared, `set -e` makes an unexpected failure
# stop the run instead of continuing half-installed, and the daemon source for the helper is an internal variable
# (never RAMPART_DAEMON_SRC from the environment). The wrappers (install.sh, uninstall.sh, postinstall) additionally
# start this script under `env -i`, so BASH_ENV can't inject code before the first line runs.
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH
unset BASH_ENV ENV CDPATH GLOBIGNORE MAILPATH PS4 SHELLOPTS 2>/dev/null || true
IFS=$' \t\n'
for v in $(env | sed -n 's/^\(DYLD_[A-Za-z0-9_]*\|LD_[A-Za-z0-9_]*\)=.*/\1/p'); do unset "$v"; done
umask 022

ACTION="${1:-}"; shift || true
DRY=0; KEEP_DATA=0; ALLOW_DOWNGRADE=0; EXPECT_CDHASH=""; POS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --keep-data) KEEP_DATA=1 ;;
    --allow-downgrade) ALLOW_DOWNGRADE=1 ;;
    --expect-cdhash) shift; EXPECT_CDHASH="${1:-}" ;;
    -*) echo "unknown option $1" >&2; exit 64 ;;
    *) POS+=("$1") ;;
  esac
  shift
done

APP="${RAMPART_APP:-/Applications/Rampart.app}"
LABEL_D="app.rampart.daemon"
LABEL_A="app.rampart.agent"
HELPER_DIR="/Library/PrivilegedHelperTools"
HELPER="$HELPER_DIR/app.rampart.daemon"
DAEMON_PLIST="/Library/LaunchDaemons/$LABEL_D.plist"
AGENT_PLIST="/Library/LaunchAgents/$LABEL_A.plist"
SUPPORT="/Library/Application Support/Rampart"
LOGS="/Library/Logs/Rampart"
SOCKET="/var/run/rampart.sock"
CLI_LINK="/usr/local/bin/rampart"
PKG_ID="app.rampart.app.pkg"
BUNDLE_ID="app.rampart.app"
DAEMON_ID="app.rampart.daemon"
STAGE_PREFIX="/private/tmp/app.rampart.stage"
# Daemon binary to install when it comes from our root-only staging folder (set by place_staged only; an environment
# variable of the same purpose used to be honoured, which let a caller that controls the env of the `install` action
# name any ad-hoc-signed file in a root-owned folder such as /private/tmp).
DAEMON_SRC=""
unset RAMPART_DAEMON_SRC
# Identity pinned at install (root-owned, one source of truth for updates, Guard and the updater):
# signer (Team ID / designated requirement, or "adhoc" + exact cdhashes), version and build.
IDENTITY="$SUPPORT/install-identity.plist"
# Fixture roots are honoured only in --dry-run, so they can never redirect a real (root) run.
USERS_DIR="/Users"
if [ "$DRY" = 1 ]; then USERS_DIR="${RAMPART_TEST_USERS_DIR:-/Users}"; IDENTITY="${RAMPART_TEST_IDENTITY:-$IDENTITY}"; fi

run() {
  if [ "$DRY" = 1 ]; then printf '[dry-run]'; printf ' %q' "$@"; printf '\n'; return 0; fi
  "$@"
}
die() { echo "rampart-setup: $*" >&2; exit "${DIE_CODE:-65}"; }
need_root() {
  if [ "$DRY" = 0 ] && [ "$(id -u)" != 0 ]; then echo "rampart-setup: $ACTION needs root (use sudo)" >&2; exit 77; fi
}
console_uid() { stat -f %u /dev/console 2>/dev/null || echo 0; }
has_ctl() { case "$1" in *[[:cntrl:]]*) return 0 ;; esac; return 1; }

# --- identity / version helpers -------------------------------------------------------------------------
plist_get() { plutil -extract "$2" raw -o - "$1/Contents/Info.plist" 2>/dev/null || true; }
is_ours() { [ -d "$1" ] && [ ! -L "$1" ] && [ "$(plist_get "$1" CFBundleIdentifier)" = "$BUNDLE_ID" ]; }
# Code identity of a bundle or binary: the CDHash of EVERY architecture slice ("arm64=<hex>,x86_64=<hex>"),
# so a pin can't be dodged by re-signing only the slice that isn't checked.
cdhash_of() {
  local f="$1" exe arch h out=""
  exe="$f"; [ -d "$f" ] && exe="$f/Contents/MacOS/$(plist_get "$f" CFBundleExecutable)"
  for arch in $(lipo -archs "$exe" 2>/dev/null); do
    h=$(codesign -dvvv --arch "$arch" "$f" 2>&1 | sed -n 's/^CDHash=//p' | head -1 | tr 'A-F' 'a-f')
    [[ "$h" =~ ^[0-9a-f]{40}$ ]] || return 1
    out="${out:+$out,}$arch=$h"
  done
  [ -n "$out" ] && printf '%s\n' "$out"
}
is_adhoc() { local o; o=$(codesign -dv "$1" 2>&1); [[ "$o" == *$'\n'Signature=adhoc* ]]; }  # no grep -q: SIGPIPE + pipefail
valid_cdhash() { [[ "$1" =~ ^[a-z0-9_.]{1,16}=[0-9a-f]{40}(,[a-z0-9_.]{1,16}=[0-9a-f]{40}){0,7}$ ]]; }

# ver_cmp A B -> prints -1, 0 or 1 (dot-separated numeric components; anything unparsable is "bad").
ver_cmp() {
  local a="$1" b="$2"
  [[ "$a" =~ ^[0-9]{1,15}(\.[0-9]{1,15}){0,5}$ ]] && [[ "$b" =~ ^[0-9]{1,15}(\.[0-9]{1,15}){0,5}$ ]] || { echo bad; return; }
  local IFS=.; local -a x=($a) y=($b); unset IFS
  local n=${#x[@]} i p q; [ ${#y[@]} -gt "$n" ] && n=${#y[@]}
  for ((i = 0; i < n; i++)); do
    p=$((10#${x[i]:-0})); q=$((10#${y[i]:-0}))
    if [ "$p" -lt "$q" ]; then echo -1; return; fi
    if [ "$p" -gt "$q" ]; then echo 1; return; fi
  done
  echo 0
}
# Refuses NEW older than OLD (short version, then build number) unless --allow-downgrade.
check_not_downgrade() {
  local new="$1" old="$2" c
  [ "$ALLOW_DOWNGRADE" = 1 ] && return 0
  c=$(ver_cmp "$(plist_get "$new" CFBundleShortVersionString)" "$(plist_get "$old" CFBundleShortVersionString)")
  if [ "$c" = 0 ]; then c=$(ver_cmp "$(plist_get "$new" CFBundleVersion)" "$(plist_get "$old" CFBundleVersion)"); fi
  case "$c" in
    -1) die "refusing to downgrade $old (pass --allow-downgrade to force)" ;;
    bad) die "unreadable version in $new or $old; refusing to replace (pass --allow-downgrade to force)" ;;
  esac
}

# --- install identity pin -------------------------------------------------------------------------------
team_of() { codesign -dv "$1" 2>&1 | sed -n 's/^TeamIdentifier=//p' | head -1 || true; }
dr_of() { codesign -d -r- "$1" 2>&1 | sed -n 's/^designated => //p' | head -1 || true; }
# Prints the identity record (XML plist) of APP; the helper's cdhash is that of the bundle's rampartd.
identity_record() {
  local app="$1" team dr kind=signed
  team=$(team_of "$app"); [ "$team" = "not set" ] && team=""
  is_adhoc "$app" && kind=adhoc
  dr=""; [ "$kind" = signed ] && dr=$(dr_of "$app")
  local t; t=$(mktemp -t rampart-id) || return 1
  plutil -create xml1 "$t" && plutil -insert signature -string "$kind" "$t" && plutil -insert teamID -string "$team" "$t" \
    && plutil -insert requirement -string "$dr" "$t" && plutil -insert appCDHash -string "$(cdhash_of "$app")" "$t" \
    && plutil -insert daemonCDHash -string "$(cdhash_of "$app/Contents/MacOS/rampartd")" "$t" \
    && plutil -insert version -string "$(plist_get "$app" CFBundleShortVersionString)" "$t" \
    && plutil -insert build -string "$(plist_get "$app" CFBundleVersion)" "$t" && cat "$t"
  local rc=$?; rm -f "$t"; return $rc
}
rec_get() { plutil -extract "$2" raw -o - "$1" 2>/dev/null || true; }
# Why NEW may not replace what the record pins (empty = allowed). PIN is the cdhash the user approved in
# this very run (admin prompt / sudo), or empty for an unattended path.
#  - versions never roll back below the recorded install (even if /Applications was swapped meanwhile);
#  - a recorded Team ID / certificate requirement must still be satisfied (a different signer is refused);
#  - ad-hoc builds have no signer: the new copy must equal the recorded cdhash, or be explicitly approved
#    by cdhash in this run; an ad-hoc copy never replaces a certificate-signed install.
identity_refusal() {
  local new="$1" pin="$2" rec="$3" c
  [ -f "$rec" ] || return 0
  if [ "${READ_ONLY_CHECK:-0}" = 0 ] && { [ "$DRY" = 0 ] || [ -z "${RAMPART_TEST_IDENTITY:-}" ]; }; then
    [ ! -L "$rec" ] && [ "$(stat -f %u "$rec")" = 0 ] || { echo "the install record $rec is not root-owned"; return 0; }
  fi
  if [ "$ALLOW_DOWNGRADE" = 0 ]; then
    c=$(ver_cmp "$(plist_get "$new" CFBundleShortVersionString)" "$(rec_get "$rec" version)")
    [ "$c" = 0 ] && c=$(ver_cmp "$(plist_get "$new" CFBundleVersion)" "$(rec_get "$rec" build)")
    case "$c" in -1) echo "version rollback below the installed $(rec_get "$rec" version) ($(rec_get "$rec" build))"; return ;;
                 bad) echo "unreadable version"; return ;; esac
  fi
  local team req kind newteam
  kind=$(rec_get "$rec" signature); team=$(rec_get "$rec" teamID); req=$(rec_get "$rec" requirement)
  if [ "$kind" = signed ]; then
    is_adhoc "$new" && { echo "an ad-hoc copy can't replace an install signed by ${team:-a certificate}"; return; }
    newteam=$(team_of "$new"); [ "$newteam" = "not set" ] && newteam=""
    [ "$newteam" = "$team" ] || { echo "signed by Team ID '${newteam:-none}', the install is pinned to '${team:-none}'"; return; }
    if [ -n "$req" ]; then codesign --verify -R="$req" "$new" >/dev/null 2>&1 || { echo "not signed by the pinned certificate"; return; }; fi
  else
    local have; have=$(cdhash_of "$new") || have=""
    [ "$have" = "$(rec_get "$rec" appCDHash)" ] && return 0
    [ -n "$pin" ] && [ "$have" = "$pin" ] && return 0
    echo "ad-hoc build with unrecorded code hashes and no explicit approval of them"
  fi
}
record_identity() {
  local app="$1"
  if [ "$DRY" = 1 ]; then printf '[dry-run] record signer, cdhashes and version of %q in %q (root:wheel 644)\n' "$app" "$IDENTITY"; return 0; fi
  identity_record "$app" | write_root_file "$IDENTITY" 644 || die "can't record the install identity"
}
# hx10 #15: install-time client pins. The root daemon accepts privileged calls only from RamPart's app and CLI whose
# cdhash is listed here (root:wheel 644; ignored unless root-owned and not group/world-writable).
TRUSTED_CLIENTS="$SUPPORT/trusted-clients.json"
trusted_clients_json() {
  local app="$1" f h out=""
  for f in "$app/Contents/MacOS/$(plist_get "$app" CFBundleExecutable)" "$app/Contents/Helpers/rampart"; do
    [ -f "$f" ] && [ ! -L "$f" ] || continue
    h=$(cdhash_of "$f") || return 1
    for h in ${h//,/ }; do out="${out:+$out,}\"${h#*=}\""; done
  done
  [ -n "$out" ] || return 1
  printf '[%s]\n' "$out"
}
record_trusted_clients() {
  local app="$1" tmp json
  if [ "$DRY" = 1 ]; then printf '[dry-run] write cdhash pins of %q app + CLI to %q (root:wheel 644)\n' "$app" "$TRUSTED_CLIENTS"; return 0; fi
  json=$(trusted_clients_json "$app") || die "can't read the app/CLI cdhashes for $TRUSTED_CLIENTS"
  tmp=$(mktemp "$SUPPORT/.rampart.XXXXXX") || die "can't write $TRUSTED_CLIENTS"
  if printf '%s' "$json" >"$tmp" && chown root:wheel "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$TRUSTED_CLIENTS"; then return 0; fi
  rm -f "$tmp"; die "can't write $TRUSTED_CLIENTS"
}

# Only ever touch a top-level bundle in /Applications (a dry run may name a build folder).
valid_app_target() {
  local p="$1" name
  has_ctl "$p" && return 1
  # Only `install --dry-run` (a developer previewing a build folder) may name a bundle elsewhere.
  case "$p" in /Applications/*.app) ;; *) [ "$DRY" = 1 ] && [ "$ACTION" = install ] && case "$p" in *.app) return 0 ;; esac; return 1 ;; esac
  name="${p#/Applications/}"
  case "$name" in */*|.*|"") return 1 ;; esac
  return 0
}

# Strict signature + identity check of a bundle (optionally pinned to an exact cdhash).
verify_bundle() {
  local app="$1" pin="${2:-}" req="identifier \"$BUNDLE_ID\""
  if [ -n "$pin" ]; then valid_cdhash "$pin" || die "bad --expect-cdhash"; fi
  [ "$DRY" = 1 ] && { echo "[dry-run] codesign --verify --strict --deep -R='$req' $(printf %q "$app")${pin:+ and require cdhash $pin}"; return 0; }
  [ -d "$app" ] && [ ! -L "$app" ] || die "$app is not a bundle"
  codesign --verify --strict --deep -R="$req" "$app" >/dev/null 2>&1 || die "$app fails signature verification ($req)"
  # --verify proved every file matches the CodeDirectory; the CDHash pins that CodeDirectory to the approved one.
  if [ -n "$pin" ] && [ "$(cdhash_of "$app")" != "$pin" ]; then die "$app changed after it was approved (cdhash mismatch)"; fi
  [ "$(plist_get "$app" CFBundleIdentifier)" = "$BUNDLE_ID" ] || die "$app is not $BUNDLE_ID"
  [ -f "$app/Contents/MacOS/rampartd" ] && [ ! -L "$app/Contents/MacOS/rampartd" ] || die "$app has no rampartd"
}

# A folder only root can write (fixed system folders: never chmod them, just refuse if they're unsafe).
check_root_dir() {
  local d="$1"
  [ "$DRY" = 1 ] && { echo "[dry-run] check $d is a root-owned directory not writable by group/other"; return 0; }
  [ -d "$d" ] && [ ! -L "$d" ] || die "$d is missing or a symlink"
  [ "$(stat -f %u "$d")" = 0 ] || die "$d is not owned by root"
  [ $(( 0$(stat -f %Lp "$d") & 022 )) = 0 ] || die "$d is writable by group/other"
}
# Our own folders: a symlink or a non-root folder there (planted before install) is set aside, never followed.
ensure_root_dir() {
  local d="$1" m="$2"
  if [ -L "$d" ]; then run rm -f "$d"
  elif [ -e "$d" ] && [ "$(stat -f %u "$d")" != 0 ]; then run mv "$d" "$d.untrusted.$(date +%s)"; fi
  run install -d -o root -g wheel -m "$m" "$d"
}
# Writes stdin to DEST atomically (temp file in the same root-only folder, then rename over DEST: a symlink
# at DEST is replaced, not followed).
write_root_file() {
  local dest="$1" mode="$2" tmp
  if [ "$DRY" = 1 ]; then printf '[dry-run] write %q (root:wheel %s, atomic rename)\n' "$dest" "$mode"; cat >/dev/null; return 0; fi
  tmp=$(mktemp "$(dirname "$dest")/.rampart.XXXXXX") || return 1
  if cat >"$tmp" && chown root:wheel "$tmp" && chmod "$mode" "$tmp" && plutil -lint "$tmp" >/dev/null && mv -f "$tmp" "$dest"; then return 0; fi
  rm -f "$tmp"; return 1
}

daemon_plist() {
  cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$LABEL_D</string>
    <key>ProgramArguments</key>
    <array>
        <string>$HELPER</string>
    </array>
    <key>AssociatedBundleIdentifiers</key><array><string>$BUNDLE_ID</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>ThrottleInterval</key><integer>10</integer>
    <key>ProcessType</key><string>Standard</string>
    <key>ExitTimeOut</key><integer>20</integer>
    <key>SoftResourceLimits</key><dict><key>NumberOfFiles</key><integer>4096</integer></dict>
    <key>StandardOutPath</key><string>$LOGS/rampartd.out.log</string>
    <key>StandardErrorPath</key><string>$LOGS/rampartd.out.log</string>
</dict>
</plist>
EOF
}
agent_plist() {
  cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$LABEL_A</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/Rampart.app/Contents/MacOS/Rampart</string>
        <string>--background</string>
    </array>
    <key>AssociatedBundleIdentifiers</key><array><string>$BUNDLE_ID</string></array>
    <key>LimitLoadToSessionType</key><string>Aqua</string>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
    <key>ThrottleInterval</key><integer>30</integer>
    <key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
EOF
}

# Copies the daemon binary into PrivilegedHelperTools: temp file in that root-only folder, verify the COPY
# (identity, optional cdhash), then rename over the helper. $1 must already be root-controlled.
install_helper_from() {
  local src="$1" pin="${2:-}" tmp req="identifier \"$DAEMON_ID\""
  if [ "$DRY" = 1 ]; then
    printf '[dry-run] copy %q -> %q via a temp file, verify -R=%q, chown root:wheel, chmod 755, rename\n' "$src" "$HELPER" "$req"
    return 0
  fi
  tmp=$(mktemp "$HELPER_DIR/.$DAEMON_ID.XXXXXX") || die "can't create a temp file in $HELPER_DIR"
  if ! { cat <"$src" >"$tmp" && chown root:wheel "$tmp" && chmod 755 "$tmp"; }; then rm -f "$tmp"; die "copying rampartd failed"; fi
  if ! codesign --verify --strict -R="$req" "$tmp" >/dev/null 2>&1; then rm -f "$tmp"; die "rampartd fails signature verification ($req)"; fi
  if [ -n "$pin" ] && [ "$(cdhash_of "$tmp")" != "$pin" ]; then rm -f "$tmp"; die "rampartd changed while it was being copied"; fi
  mv -f "$tmp" "$HELPER" || { rm -f "$tmp"; die "can't place $HELPER"; }
  [ ! -L "$HELPER" ] && [ "$(stat -f %u "$HELPER")" = 0 ] && [ "$(stat -f %Lp "$HELPER")" = 755 ] || die "$HELPER has unsafe ownership"
}

# .pkg path: the payload in /Applications is root-owned, but /Applications itself is admin-writable, so the
# bundle could be renamed and replaced by another admin process. Open the binary ONCE, prove through the
# descriptor that it is a root-owned file not writable by others, and copy from that descriptor.
install_helper_from_bundle() {
  local src="$APP/Contents/MacOS/rampartd" pin
  if [ "$DRY" = 1 ]; then echo "[dry-run] open $(printf %q "$src") once; require root owner, no group/other write, not a symlink"; install_helper_from "$src"; return; fi
  [ ! -L "$src" ] || die "$src is a symlink"
  exec 4<"$src" || die "can't open $src"
  local fd_id path_id mode
  { fd_id=$(stat -f '%u:%i' /dev/fd/4) && path_id=$(stat -f '%u:%i' "$src") && mode=$(stat -f %Lp "$src"); } || { exec 4<&-; die "can't stat $src"; }
  [ "$fd_id" = "$path_id" ] && [ "${fd_id%%:*}" = 0 ] && [ $(( 0$mode & 022 )) = 0 ] || { exec 4<&-; die "$src is not a root-owned, root-only-writable file"; }
  install_helper_from /dev/fd/4
  exec 4<&-
}

install_rampart() {
  need_root
  valid_app_target "$APP" || die "refusing app path $APP (must be /Applications/<name>.app)"
  if [ "$DRY" = 0 ]; then is_ours "$APP" || DIE_CODE=66 die "$APP is not $BUNDLE_ID"; fi
  echo "==> Installing the Rampart protection service"
  # Upgrade: stop the old service first.
  run launchctl bootout "system/$LABEL_D" 2>/dev/null || true
  check_root_dir "$HELPER_DIR"; check_root_dir /Library/LaunchDaemons; check_root_dir /Library/LaunchAgents
  if [ -n "$DAEMON_SRC" ]; then
    # Set only by place_staged: the binary sits in our root-only staging folder (mode 700, root, under STAGE_PREFIX).
    local sdir; sdir=$(dirname "$DAEMON_SRC")
    case "$sdir" in "$STAGE_PREFIX".*) ;; *) die "daemon source $DAEMON_SRC is not in a staging folder" ;; esac
    if [ "$DRY" = 1 ]; then install_helper_from "$DAEMON_SRC"
    else
      [ ! -L "$sdir" ] && [ "$(stat -f %u "$sdir")" = 0 ] && [ "$(stat -f %Lp "$sdir")" = 700 ] || die "daemon source folder is not root-only"
      [ -f "$DAEMON_SRC" ] && [ ! -L "$DAEMON_SRC" ] || die "daemon source is not a regular file"
      local spin; spin=$(cdhash_of "$DAEMON_SRC") || die "can't read the cdhash of the staged rampartd"
      install_helper_from "$DAEMON_SRC" "$spin"
    fi
  else
    install_helper_from_bundle
  fi
  ensure_root_dir "$SUPPORT" 755
  ensure_root_dir "$LOGS" 755
  daemon_plist | write_root_file "$DAEMON_PLIST" 644 || die "can't write $DAEMON_PLIST"
  agent_plist | write_root_file "$AGENT_PLIST" 644 || die "can't write $AGENT_PLIST"
  # The old job may still be exiting (ExitTimeOut 20): retry, then fail loudly instead of leaving no service.
  local try=0
  until run launchctl bootstrap system "$DAEMON_PLIST"; do
    try=$((try + 1)); [ "$try" -lt 30 ] || die "launchctl bootstrap system/$LABEL_D failed"
    sleep 1
  done
  run launchctl enable "system/$LABEL_D" || true
  # Command line tool (/usr/local/bin is often owned by the admin user; a failure here is not an install failure).
  run install -d -m 755 /usr/local/bin || true
  if [ -e "$CLI_LINK" ] && [ ! -L "$CLI_LINK" ]; then echo "    not replacing $CLI_LINK: it is not a symlink" >&2
  else run ln -sfn "$APP/Contents/Helpers/rampart" "$CLI_LINK" || echo "    could not create $CLI_LINK" >&2; fi
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

# Refuses a source anyone can modify (world-writable file/folder anywhere in the bundle).
check_source_not_world_writable() {
  local src="$1" bad
  bad=$(find "$src" -perm -0002 ! -type l -print -quit 2>/dev/null) || true
  [ -z "$bad" ] || die "refusing $src: $bad is writable by every user"
}
# Refuses a bundle containing symlinks or hard-linked files: root later runs chown/chmod -R and ditto over the copy, and a
# link can point outside the bundle (a target in /etc, another user's file). Our bundle never contains links.
check_source_no_links() {
  local src="$1" bad
  bad=$(find "$src" \( -type l -o \( -type f -links +1 \) \) -print -quit 2>/dev/null) || true
  [ -z "$bad" ] || die "refusing $src: $bad is a symlink or hard link"
}

# install-from SRC: stage + verify + place. The cdhash is pinned from SRC before the copy (or given with
# --expect-cdhash), and the root-only staged copy must match it exactly.
install_from() {
  need_root
  local src="${POS[0]:-}" dest="${POS[1]:-/Applications/Rampart.app}" pin="$EXPECT_CDHASH" stage
  [ -n "$src" ] && [ -d "$src" ] || DIE_CODE=66 die "install-from: source bundle not found"
  has_ctl "$src" && die "refusing a path with control characters"
  valid_app_target "$dest" || die "refusing destination $dest"
  check_source_not_world_writable "$src"
  check_source_no_links "$src"
  if [ -z "$pin" ]; then
    codesign --verify --strict --deep -R="identifier \"$BUNDLE_ID\"" "$src" >/dev/null 2>&1 || die "$src fails signature verification"
    pin=$(cdhash_of "$src") || die "can't read the cdhash of $src"
  fi
  valid_cdhash "$pin" || die "can't read the cdhash of $src"
  if [ "$DRY" = 1 ]; then
    stage="$STAGE_PREFIX.DRYRUN"
    echo "[dry-run] mktemp -d $STAGE_PREFIX.XXXXXX (root, mode 700)"
    printf '[dry-run] ditto %q %q, chown -R root:wheel, chmod -R go-w, strip quarantine\n' "$src" "$stage/Rampart.app"
  else
    stage=$(mktemp -d "$STAGE_PREFIX.XXXXXX") || die "mktemp failed"
    STAGE_DIR="$stage"; trap 'rm -rf "$STAGE_DIR"' EXIT
    ditto "$src" "$stage/Rampart.app" || die "copy failed"
    check_source_no_links "$stage/Rampart.app"   # the copy is ours now; a link that slipped in mid-copy fails the install
    chown -R -h root:wheel "$stage/Rampart.app" && chmod -R -P go-w "$stage/Rampart.app" || die "copy failed"
    xattr -dr com.apple.quarantine "$stage/Rampart.app" 2>/dev/null || true
  fi
  verify_bundle "$stage/Rampart.app" "$pin"
  POS=("$stage" "$dest"); place_staged
}

# place-staged STAGE DEST: STAGE is a root-only folder holding Rampart.app (copied and verified by root).
place_staged() {
  need_root
  local stage="${POS[0]:-}" dest="${POS[1]:-/Applications/Rampart.app}" app
  app="$stage/Rampart.app"
  valid_app_target "$dest" || die "refusing destination $dest"
  case "$stage" in "$STAGE_PREFIX".*) ;; *) die "refusing staging folder $stage" ;; esac
  has_ctl "$stage" && die "refusing staging folder $stage"
  if [ "$DRY" = 0 ]; then
    [ -d "$stage" ] && [ ! -L "$stage" ] && [ "$(stat -f %u "$stage")" = 0 ] && [ "$(stat -f %Lp "$stage")" = 700 ] || die "$stage is not a root-only folder"
  fi
  verify_bundle "$app" "$EXPECT_CDHASH"
  if [ "$DRY" = 0 ] || [ -n "${RAMPART_TEST_IDENTITY:-}" ]; then
    local why; why=$(identity_refusal "$app" "$EXPECT_CDHASH" "$IDENTITY") || why="${why:-the install record could not be checked}"
    [ -z "$why" ] || die "refusing this update: $why"
  else echo "[dry-run] check $(printf %q "$app") against the install record $IDENTITY (signer, cdhash, no rollback)"
  fi
  if [ -L "$dest" ]; then run rm -f "$dest"
  elif [ -e "$dest" ]; then
    is_ours "$dest" || die "$dest exists and is not $BUNDLE_ID; refusing to replace it"
    if [ "$DRY" = 0 ]; then
      check_not_downgrade "$app" "$dest"
      # Same signer as the copy being replaced (only meaningful with a real certificate; ad-hoc has none).
      if ! is_adhoc "$dest"; then
        local dr; dr=$(codesign -d -r- "$dest" 2>&1 | sed -n 's/^designated => //p') || dr=""
        [ -n "$dr" ] && codesign --verify -R="$dr" "$app" >/dev/null 2>&1 || die "the new copy isn't signed by the same identity as $dest"
      fi
    else echo "[dry-run] check $(printf %q "$dest") is not newer (refuse downgrade) and has the same signer"
    fi
  fi
  # Keep the daemon binary and this verified copy inside the root-only folder; /Applications is admin-writable.
  run cp "$app/Contents/MacOS/rampartd" "$stage/rampartd" || die "can't stage rampartd"
  if [ -e "$dest" ] && [ ! -L "$dest" ]; then run mv "$dest" "$stage/previous.app" || die "can't move the old copy aside"; fi
  if ! run mv "$app" "$dest"; then
    [ -d "$stage/previous.app" ] && mv "$stage/previous.app" "$dest"
    die "can't place $dest"
  fi
  run rm -rf "$stage/previous.app"
  APP="$dest"
  DAEMON_SRC="$stage/rampartd" install_rampart
  DAEMON_SRC=""
  record_identity "$dest"
  record_trusted_clients "$dest"
}

restore_dns() {
  # rampartd restores DNS itself on SIGTERM; this is the fallback if it was killed.
  local snap="$SUPPORT/dns-original.json"
  [ -f "$snap" ] && [ ! -L "$snap" ] || return 0
  # Trust the snapshot only if root wrote it (an admin process could plant one in a non-root folder).
  [ "$(stat -f %u "$SUPPORT")" = 0 ] && [ "$(stat -f %u "$snap")" = 0 ] || { echo "    skipping DNS restore: $snap is not root-owned" >&2; return 0; }
  echo "==> Restoring DNS settings from $snap"
  local n i svc servers
  n=$(plutil -extract services raw -o - "$snap" 2>/dev/null || echo 0)
  [[ "$n" =~ ^[0-9]{1,3}$ ]] || n=0
  for ((i = 0; i < n; i++)); do
    svc=$(plutil -extract "services.$i.service" raw -o - "$snap" 2>/dev/null) || continue
    case "$svc" in -*|*[[:cntrl:]]*|"") continue ;; esac
    servers=()
    local m j s
    m=$(plutil -extract "services.$i.servers" raw -o - "$snap" 2>/dev/null || echo 0)
    [[ "$m" =~ ^[0-9]{1,2}$ ]] || m=0
    for ((j = 0; j < m; j++)); do
      s=$(plutil -extract "services.$i.servers.$j" raw -o - "$snap" 2>/dev/null) || continue
      [[ "$s" =~ ^[0-9A-Fa-f:.]{2,45}$ ]] && servers+=("$s")
    done
    if [ "${#servers[@]}" = 0 ]; then run networksetup -setdnsservers "$svc" empty || true
    else run networksetup -setdnsservers "$svc" "${servers[@]}" || true; fi
  done
  run dscacheutil -flushcache || true; run killall -HUP mDNSResponder 2>/dev/null || true
}

# Prints HOME/REL only if every folder between HOME and REL's last component is a real folder (not a
# symlink) owned by the home's owner or root. Deletion then runs AS that user, so even a race can only
# delete what the user could delete anyway.
safe_user_path() {
  local home="$1" rel="$2" uid cur o i
  [ -d "$home" ] && [ ! -L "$home" ] || return 1
  uid=$(stat -f %u "$home") || return 1
  local IFS=/; local -a parts=($rel); unset IFS
  cur="$home"
  for ((i = 0; i < ${#parts[@]} - 1; i++)); do
    cur="$cur/${parts[i]}"
    [ -d "$cur" ] && [ ! -L "$cur" ] || return 1
    o=$(stat -f %u "$cur") || return 1; [ "$o" = "$uid" ] || [ "$o" = 0 ] || return 1
  done
  printf '%s\n' "$home/$rel"
}
user_rm() { # uid path...
  local uid="$1"; shift
  if [ "$DRY" = 1 ]; then run rm -rf -- "$@"; return 0; fi
  /usr/bin/sudo -n -u "#$uid" /bin/rm -rf -- "$@" 2>/dev/null || true
}

uninstall_rampart() {
  need_root
  valid_app_target "$APP" || die "refusing app path $APP (must be /Applications/<name>.app)"
  echo "==> Stopping Rampart"
  run launchctl bootout "system/$LABEL_D" 2>/dev/null || true
  local home uid
  for home in "$USERS_DIR"/*; do
    uid=$(stat -f %u "$home" 2>/dev/null) || continue
    [ "$uid" -ge 500 ] 2>/dev/null || continue
    run launchctl bootout "gui/$uid/$LABEL_A" 2>/dev/null || true
    run launchctl bootout "gui/$uid/app.rampart.userdaemon" 2>/dev/null || true
  done
  run pkill -x rampartd 2>/dev/null || true
  run pkill -f "$HELPER" 2>/dev/null || true
  run pkill -x Rampart 2>/dev/null || true
  restore_dns
  # pf anchors (never in pf.conf): blocklist 250, emergency 249, remote access 251, the lure, and anything else named Rampart.
  # Listed names are validated (anchor charset only) and never glob-expanded. A dry run may take the listing from a fixture.
  local listed
  if [ "$DRY" = 1 ] && [ -n "${RAMPART_TEST_PF_ANCHORS+x}" ]; then listed="$RAMPART_TEST_PF_ANCHORS"
  elif [ "$DRY" = 1 ]; then listed=""
  else listed=$( (pfctl -s Anchors 2>/dev/null; pfctl -a com.apple -s Anchors 2>/dev/null) || true); fi
  local a
  set -f
  for a in com.apple/249.RampartEmergency com.apple/250.Rampart com.apple/251.RampartRemote app.rampart/lure \
           $(printf '%s\n' "$listed" | tr -d ' \t' | grep -i rampart | sort -u || true); do
    case "$a" in *[!A-Za-z0-9._/-]*|"") echo "    skipping pf anchor with unexpected characters: $a" >&2; continue ;; esac
    run pfctl -a "$a" -F all 2>/dev/null || true
  done
  set +f

  echo "==> Removing files"
  # Fixed root-owned paths only; rm on a symlink removes the link, never its target.
  run rm -f "$DAEMON_PLIST" "$AGENT_PLIST" "$HELPER" "$SOCKET"
  if [ -L "$CLI_LINK" ] && readlink "$CLI_LINK" | grep -qi "Rampart.app"; then run rm -f "$CLI_LINK"; fi
  # The app: only a bundle that really is ours (APFS is case-insensitive: RamPart.app == Rampart.app).
  if [ -L "$APP" ]; then run rm -f "$APP"
  elif [ -e "$APP" ]; then
    if is_ours "$APP"; then run rm -rf "$APP"; else echo "    not removing $APP: it is not $BUNDLE_ID" >&2; fi
  fi
  local leftover
  for leftover in /Applications/.RamPart-installing.app /Applications/.Rampart-installing.app; do
    is_ours "$leftover" && run rm -rf "$leftover"
  done
  for leftover in "$STAGE_PREFIX".*; do
    [ -d "$leftover" ] && [ ! -L "$leftover" ] && [ "$(stat -f %u "$leftover")" = 0 ] && run rm -rf "$leftover"
  done
  for leftover in "$LOGS" "$SUPPORT"; do
    [ "$leftover" = "$SUPPORT" ] && [ "$KEEP_DATA" = 1 ] && { echo "    keeping $SUPPORT (--keep-data)"; continue; }
    if [ -L "$leftover" ]; then run rm -f "$leftover"; elif [ -e "$leftover" ]; then run rm -rf "$leftover"; fi
  done
  local rel p
  for home in "$USERS_DIR"/*; do
    [ -d "$home/Library" ] || continue
    uid=$(stat -f %u "$home" 2>/dev/null) || continue
    [ "$uid" -ge 500 ] 2>/dev/null || continue
    local rels=("Library/LaunchAgents/$LABEL_A.plist" "Library/LaunchAgents/$BUNDLE_ID.plist"
                "Library/Caches/$BUNDLE_ID" "Library/HTTPStorages/$BUNDLE_ID"
                "Library/Saved Application State/$BUNDLE_ID.savedState" "Library/Preferences/$BUNDLE_ID.plist")
    [ "$KEEP_DATA" = 0 ] && rels+=("Library/Application Support/Rampart")
    for rel in "${rels[@]}"; do
      [ -e "$home/$rel" ] || [ -L "$home/$rel" ] || continue
      if p=$(safe_user_path "$home" "$rel"); then user_rm "$uid" "$p"
      else echo "    skipping $home/$rel: a folder on its path is a symlink or owned by someone else" >&2; fi
    done
  done
  run pkgutil --forget "$PKG_ID" 2>/dev/null || true
  run tccutil reset All "$BUNDLE_ID" 2>/dev/null || true
  if [ "$DRY" = 0 ]; then verify_removed; else echo "[dry-run] would verify nothing is left"; fi
}

# Exit 0 only if no trace of Rampart remains.
verify_removed() {
  local left=()
  local paths=("$DAEMON_PLIST" "$AGENT_PLIST" "$HELPER" "$SOCKET" "$LOGS")
  [ "$KEEP_DATA" = 0 ] && paths+=("$SUPPORT")
  is_ours "$APP" && paths+=("$APP")
  for p in "${paths[@]}"; do if [ -e "$p" ] || [ -L "$p" ]; then left+=("$p"); fi; done
  for p in "$STAGE_PREFIX".*; do [ -e "$p" ] && left+=("$p"); done
  if [ -L "$CLI_LINK" ] && readlink "$CLI_LINK" | grep -qi "Rampart.app"; then left+=("$CLI_LINK"); fi
  for home in "$USERS_DIR"/*; do
    for p in "$home/Library/LaunchAgents/$LABEL_A.plist" "$home/Library/Preferences/$BUNDLE_ID.plist"; do
      [ -e "$p" ] && left+=("$p")
    done
    [ "$KEEP_DATA" = 0 ] && [ -e "$home/Library/Application Support/Rampart" ] && left+=("$home/Library/Application Support/Rampart")
  done
  launchctl print "system/$LABEL_D" >/dev/null 2>&1 && left+=("launchd job system/$LABEL_D")
  pgrep -x rampartd >/dev/null 2>&1 && left+=("running rampartd process")
  pgrep -f "$HELPER" >/dev/null 2>&1 && left+=("running $HELPER process")
  local pkgs; pkgs=$(pkgutil --pkgs 2>/dev/null) || pkgs=""
  grep -qx "$PKG_ID" <<<"$pkgs" && left+=("pkg receipt $PKG_ID")
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
  for p in "$HELPER" "$DAEMON_PLIST"; do
    if [ -e "$p" ] && { [ -L "$p" ] || [ "$(stat -f %u "$p")" != 0 ] || [ $(( 0$(stat -f %Lp "$p") & 022 )) != 0 ]; }; then
      echo "UNSAFE  $p (must be a root-owned file writable only by root)"; ok=1
    fi
  done
  if launchctl print "system/$LABEL_D" >/dev/null 2>&1; then echo "ok    launchd job system/$LABEL_D"
  else echo "MISSING launchd job system/$LABEL_D (needs root to see)"; ok=1; fi
  [ -S "$SOCKET" ] && echo "ok    $SOCKET" || { echo "MISSING $SOCKET"; ok=1; }
  return $ok
}

case "$ACTION" in
  install)
    # .pkg path: Installer was the user's approval; still never roll back or change signer.
    if [ "$DRY" = 0 ]; then why=$(identity_refusal "$APP" "$(cdhash_of "$APP")" "$IDENTITY"); [ -z "$why" ] || die "refusing this update: $why"; fi
    install_rampart; record_identity "$APP"; record_trusted_clients "$APP" ;;
  install-from) install_from ;;
  place-staged) place_staged ;;
  uninstall) uninstall_rampart ;;
  verify) verify_installed ;;
  verify-removed) verify_removed ;;
  print-plist) case "${POS[0]:-}" in daemon) daemon_plist ;; agent) agent_plist ;; *) exit 64 ;; esac ;;
  ver-cmp) ver_cmp "${POS[0]:-}" "${POS[1]:-}" ;;
  cdhash) cdhash_of "${POS[0]:-}" ;;
  identity-record) identity_record "${POS[0]:-}" ;;
  check-update) why=$(READ_ONLY_CHECK=1 identity_refusal "${POS[0]:-}" "$EXPECT_CDHASH" "${POS[1]:-$IDENTITY}"); [ -z "$why" ] && echo ok || { echo "refused: $why"; exit 65; } ;;   # read-only
  verify-bundle) DRY=0; verify_bundle "${POS[0]:-}" "$EXPECT_CDHASH"; echo "ok" ;;   # read-only check
  *) echo "usage: rampart-setup.sh install|install-from SRC|place-staged STAGE DEST|uninstall|verify|verify-removed|print-plist daemon|agent [--dry-run] [--keep-data] [--allow-downgrade] [--expect-cdhash HEX]" >&2; exit 64 ;;
esac
