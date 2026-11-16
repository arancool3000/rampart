# RamPart to-do list

Kept up to date while working. [x] done, [ ] to do, [~] in progress.

## Right now (2026-11-16 evening)
- [x] Rebuild + install: taller Guard head and new icons, true-perspective grid, marching Guard bots,
      continuous force-field shimmer, cheaper widget blinks, Stage Manager margin, user-helper retirement,
      memory relief (malloc pressure relief) in app + daemon
- [ ] After install: check CPU/RAM settle (app < 10% idle, root daemon < 5% idle, no `rampartd --user`)
- [x] Re-render the wallpaper with the new Guard + bots and set it again
- [x] Render the desktop offscreen and check the bots and grid look right

## Your Mac theme
- [x] RamPart wallpaper, teal highlight, green accent, dark mode (old values saved in ~/Pictures/RamPart/previous-theme.txt)
- [ ] Terminal "RamPart" profile (navy background, teal text) - ask first, Terminal is in daily use
- [ ] Restore command for the theme (one line) in the README

## Full Disk Access keeps dropping after updates
- [ ] Every update changes the daemon's ad-hoc signature, so macOS drops Full Disk Access and eslogger stops.
      Fix: sign builds with one stable local signing identity so the permission survives updates.
- [ ] Until then: re-enable app.rampart.daemon in Full Disk Access after each update

## Performance / battery / SSD
- [x] Serial background on-write scanning, skip build output
- [x] Scans: half the cores on power, one on battery; scheduled scans wait for power
- [x] Remote-access + nettop sampling slowed, battery-aware throttling
- [x] Cached Needs-you / open detections in the app
- [x] Retire the redundant user daemon when the root daemon runs
- [x] Return freed memory every minute (root daemon had 158 MB of fragmented free heap)
- [ ] eslogger subscribes to `open`/`close` (very chatty): measure and trim
- [ ] SSD writes: detections.json (~480 KB) and persistence-snapshot.json rewritten on every change → append-only or debounce
- [ ] Root daemon IPC: Protection.status waits on the blocklist lock during reloads
- [ ] App: 90 days / ~5,500 activity rows kept in memory → page older rows

## False alarms
- [x] Apple impersonation on Safari's BTM helpers
- [x] `date -r` clock tamper, data: URLs, local IPs, reverse-DNS entitlement strings
- [x] "Process impersonating RamPart" fires for my own dev builds in ~/Rampart/dist → ignore unsigned dev copies inside the source tree

## UI
- [x] Tech/HUD look for the app, Live Feed + Defense Grid widgets
- [ ] Main app: check every screen offscreen for anything the HUD style broke (light mode too)
- [ ] Protect Everything: confirm rows now refresh (canaries showed Off while on)

## Cat & Mouse (promised earlier)
- [ ] Restart the tarpit when the saved config has it on
- [ ] Catch unattributed FSEvents touches in user mode; forward root eslogger decoy opens
- [ ] Live demo: read a decoy, copy the AWS/SSH bait, `nc 127.0.0.1 2222`, check catches + notifications

## GitHub
- [ ] Repo github.com/arancool3000/rampart is empty: push was blocked by a FAKE Stripe test key in
      Sources/rampart-selftest/SelfTest+Hx2.swift. Needs your choice: click the unblock link, or OK for me to rewrite history.

## Later
- [ ] P02/P03 persistence checks; duplicate canary pairs from root + user daemons; flaky redteam memory test
- [ ] Windows version; iOS version (built on imac.local, SideStore)
- [ ] Name: "Rampart" trademark conflicts in security software, still undecided
