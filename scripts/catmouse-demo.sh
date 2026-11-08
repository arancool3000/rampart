#!/bin/zsh
# Cat & Mouse end-to-end demo: plays attacker (cat, cp, nc) and asserts RamPart caught it.
#
#   scripts/catmouse-demo.sh            live: uses the running session service (rampartd --user) and its decoys
#                                       (Cat & Mouse must be on: decoys + network lure). Nothing is installed.
#   scripts/catmouse-demo.sh --scratch  dev: starts a throw-away rampartd --user from .build-agents/debug with a
#                                       scratch HOME and state (RAMPART_NO_PRIVILEGED_TOOLS=1, --no-scheduler,
#                                       killed within 60 s). Build first with scripts/agent-build.sh --product rampartd.
#
# Exit 0 = every expected catch appeared in catches.json and the lure recorded the nc attempt.
setopt pipefail
cd "$(dirname "$0")/.."
MODE=live; [ "$1" = "--scratch" ] && MODE=scratch
ok=0; bad=0
pass() { print "  PASS $1"; ok=$((ok+1)); }
fail() { print "  FAIL $1"; bad=$((bad+1)); }
json() { /usr/bin/python3 -I -c "$1" "${@:2}"; }

LOOT=$(mktemp -d "${TMPDIR:-/tmp}/catmouse-loot.XXXXXX")
DPID=""
cleanup() { [ -n "$DPID" ] && kill "$DPID" 2>/dev/null; rm -rf "$LOOT"; [ -n "$SCRATCH" ] && rm -rf "$SCRATCH"; }
trap cleanup EXIT INT TERM

if [ "$MODE" = scratch ]; then
  BIN=.build-agents/debug/rampartd
  [ -x "$BIN" ] || { print "build first: scripts/agent-build.sh --product rampartd"; exit 2; }
  SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/catmouse-scratch.XXXXXX")
  SCRATCH=$(cd "$SCRATCH" && pwd -P)
  FAKEHOME="$SCRATCH/home"; STATE="$SCRATCH/state/deception"
  mkdir -p "$FAKEHOME/Desktop" "$FAKEHOME/Documents" "$STATE"
  PORT=$(json 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
  print "{\"decoysEnabled\":true,\"mazeEnabled\":true,\"tarpitEnabled\":true,\"tarpitPort\":$PORT,\"lureScope\":\"loopback\",\"decoysVisible\":false,\"tone\":\"playful\"}" > "$STATE/config.json"
  print "scratch: home $FAKEHOME, lure port $PORT"
  RAMPART_NO_PRIVILEGED_TOOLS=1 RAMPART_DECEPTION_HOME="$FAKEHOME" "$BIN" --user --no-scheduler --no-updates \
      --root "$SCRATCH/state" --socket "$SCRATCH/r.sock" >"$SCRATCH/rampartd.log" 2>&1 &
  DPID=$!
  ( sleep 55; kill $DPID 2>/dev/null ) &!          # ZERO POP-UPS rule: dev daemon never outlives 60 s
  for i in {1..40}; do [ -s "$STATE/decoys.json" ] && break; sleep 0.25; done
  sleep 4                                           # past the (dev) 3 s settle window after planting
else
  STATE="$HOME/Library/Application Support/Rampart/deception"
  [ -f "$STATE/config.json" ] || { print "Cat & Mouse has never been switched on (no $STATE/config.json)"; exit 2; }
  PORT=$(json 'import json,sys; c=json.load(open(sys.argv[1])); print(c.get("tarpitPort",2222) if c.get("tarpitEnabled") else 0)' "$STATE/config.json")
  pgrep -qf "rampartd --user" || print "warning: no 'rampartd --user' process found"
fi

# Pick the bait: a crypto seed (cat), cloud credentials + an SSH key (cp).
bait=("${(@f)$(json '
import json,sys,os
recs=[r for r in json.load(open(sys.argv[1])) if os.path.isfile(r["path"])]
for k in ("cryptoSeed","awsCredentials","sshKey"): print(next((r["path"] for r in recs if r["kind"]==k), "-"))' "$STATE/decoys.json" 2>/dev/null)}")
SEED=${bait[1]:--}; AWS=${bait[2]:--}; SSH=${bait[3]:--}
[ -n "$SEED" ] && [ "$SEED" != "-" ] || { print "no planted crypto-seed decoy found in $STATE/decoys.json"; exit 2; }
print "bait: $SEED"; print "      $AWS"; print "      $SSH"

count() { json 'import json,sys
try: print(len(json.load(open(sys.argv[1]))))
except Exception: print(0)' "$1"; }
C0=$(count "$STATE/catches.json"); T0=$(count "$STATE/tarpit.json")
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)

if [ "$PORT" != 0 ]; then
  if /usr/sbin/lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then pass "lure listening on 127.0.0.1:$PORT"; else fail "nothing listening on port $PORT (lure not started)"; fi
fi

print "attacker: cat, cp, nc ..."
cat "$SEED" >/dev/null
[ "$AWS" != "-" ] && cp "$AWS" "$LOOT/"
[ "$SSH" != "-" ] && cp "$SSH" "$LOOT/"
if [ "$PORT" != 0 ]; then
  ( printf 'admin\r\n'; sleep 1; printf 'hunter2\r\n'; sleep 2 ) | /usr/bin/nc -w 4 127.0.0.1 "$PORT" >/dev/null 2>&1
fi

# Catches arrive within ~2 s (access-time poll); a lure attempt is recorded when the session ends.
expect=("$SEED"); [ "$AWS" != "-" ] && expect+=("$AWS"); [ "$SSH" != "-" ] && expect+=("$SSH")
for i in {1..30}; do
  missing=$(json 'import json,sys
cs=json.load(open(sys.argv[1]))
seen={c["decoyPath"] for c in cs if c["date"]>=sys.argv[2]}
print(sum(1 for p in sys.argv[3:] if p not in seen))' "$STATE/catches.json" "$START" "${expect[@]}" 2>/dev/null || print 99)
  tp=$(count "$STATE/tarpit.json")
  [ "$missing" = 0 ] && { [ "$PORT" = 0 ] || [ "$tp" -gt "$T0" ]; } && break
  sleep 1
done

for p in "${expect[@]}"; do
  line=$(json 'import json,sys
for c in json.load(open(sys.argv[1])):
    if c["decoyPath"]==sys.argv[2] and c["date"]>=sys.argv[3]:
        print(c["access"], "by", c.get("processName","?"), "("+c.get("attribution","event actor")+")"); break' "$STATE/catches.json" "$p" "$START" 2>/dev/null)
  if [ -n "$line" ]; then pass "caught: ${p:t} -> $line"; else fail "no catch for ${p:t}"; fi
done
if [ "$PORT" != 0 ]; then
  tp=$(count "$STATE/tarpit.json")
  if [ "$tp" -gt "$T0" ]; then
    pass "lure recorded the nc attempt: $(json 'import json,sys; a=json.load(open(sys.argv[1]))[-1]; print(a["credentialAttempts"], "password guess(es); said:", " / ".join((a.get("replies") or [])[-2:]))' "$STATE/tarpit.json")"
  else fail "lure recorded no attempt"; fi
fi
print "catches.json: $C0 -> $(count "$STATE/catches.json") entries"
print "$ok passed, $bad failed"
[ "$bad" = 0 ]
