# 09 — UX & Design Spec for Bastion (macOS, SwiftUI)

Status: research and spec draft, 2026-11-05
Target: macOS 26 "Tahoe" and later, with Liquid Glass. Must adapt to macOS 27's Liquid Glass revisions.
Goal: calmer, faster and more honest than Norton 360 for Mac. Feels like an Apple app, not a marketing funnel.

---

## 1. Research findings

### 1.1 What users hate (Norton / McAfee)
Sources: Norton Community threads, checkthat.ai review aggregation, Apple Discussions.

| Complaint | Evidence | Bastion rule |
|---|---|---|
| Constant upsells for add-ons ($25–$70) and services the user already owns | "Is Norton 360 a marketing program? All it does is try to sell me stuff"; "tired of being hustled for more junk"; "harassing me daily" | **No in-app ads, ever.** The only purchase surface is Settings › Account. No notifications about products. |
| Pop-ups that ignore "don't ask again" | Catalina user reported prompts "every minute" despite ticked boxes; repeated prompts about `rapportd`/`sharingd` | "Don't ask again" is a persisted rule you can see and edit (Settings › Rules). Apple-signed system daemons are trusted by default. |
| Popups "worse than a virus"; uninstall was the only fix | Norton 360 update thread, 2024 | Every alert category has its own toggle. There is a global **Quiet Mode** and it respects macOS Focus. |
| Fear-based copy ("Your Mac is at RISK!", red everywhere) | Common across AV reviews | Plain, factual language. Red means "action needed now", and nothing else uses it. |
| Clutter: dozens of tiles, cross-promos, VPN/identity/cloud backup crammed into one window | Norton/McAfee dashboards | Seven sidebar items. One primary action per screen. |
| Slow and heavy UI; scans that drain the battery | General AV reviews | UI launches in under 300 ms. Scans throttle on battery and are paused by Low Power Mode. CPU use is shown, not hidden. |
| Renewal and cancellation dark patterns | r/antivirus billing complaints | Renewal date always visible. One-click "Turn off auto-renew" that links straight to the App Store or the account page. |
| Security score used as a sales lever ("Upgrade to reach 100%") | Norton Device Security score | Bastion's score only counts things the user can fix for free, on this Mac. |

### 1.2 What users love
- **Malwarebytes for Mac**: Macworld (Mar 2026) calls it clean and intuitive. The dashboard shows three facts: protection status, last scan, update status. One big Scan button. Lesson: a status-first dashboard with one primary verb.
- **Objective-See (LuLu, BlockBlock, KnockKnock)**: alerts that name the process, show its code signature and destination, and offer a VirusTotal lookup. Free and open, with no nagging. Weakness: dated UI and floods of alerts on first run (Nektony review). Lesson: copy the transparency, fix the look, and learn silently for the first 48 hours.
- **Little Snitch**: a network map, rules shown as readable sentences, a "Silent mode" with a review list afterwards, and good alert defaults (remember for "until quit" / "forever"). Lesson: rules are first-class objects the user can read and edit.
- **CleanMyMac**: polished visuals, a single "Smart Care" flow, friendly illustrations, progress that feels quick. Lesson: delight is allowed. But avoid its own upsell habits and inflated "junk found" numbers.

### 1.3 Apple HIG and Liquid Glass (macOS 26/27)
- WWDC25 "Build an AppKit app with the new design" (session 310): sidebars and inspectors get Liquid Glass automatically in `NavigationSplitView`. Drop custom sidebar materials. The sidebar floats and content can extend underneath it (`.backgroundExtensionEffect()`).
- The toolbar floats on glass. Non-interactive items such as status text should **not** have a glass backing (`.sharedBackgroundVisibility(.hidden)` on that `ToolbarItem`). Tint at most one prominent item with the accent color.
- Glass is for the **navigation/control layer**, never for content. Don't stack glass on glass. Group nearby glass elements in a `GlassEffectContainer`.
- Settings use a `Settings { }` scene: a tabbed window that opens with ⌘, and the app menu item "Settings…".
- Menu bar extra: `MenuBarExtra(...) { }.menuBarExtraStyle(.window)` for a rich popover. Users must be able to hide it.
- macOS 27 (per Cult of Mac reporting): Apple is revising Liquid Glass, with fixes to sidebar and corner radius and a uniform toolbar. **Use only system components and standard modifiers** so we pick up the fixes for free. Never hard-code corner radii; use `ConcentricRectangle` / `.containerShape`.
- Respect **Reduce Transparency** (glass becomes opaque automatically if we use system materials), **Increase Contrast**, **Reduce Motion**, and **Differentiate Without Color**.

### 1.4 Accessibility requirements
- Every status is shown with **symbol + text + color**, never color alone.
- VoiceOver: the score ring reads "Security score 86 out of 100, Good. 2 recommendations." Scan progress uses `.accessibilityValue` and posts updates no more than every 10%.
- Dynamic Type: macOS has no system Dynamic Type, but use text styles (`.body`, `.title2`) everywhere, never fixed point sizes, so the app's own "Text size" setting (Settings › General) and Accessibility zoom work.
- Full keyboard navigation: ⌘1–⌘7 switch sidebar sections, ⌘R runs a Quick Scan, ⇧⌘R runs a Full Scan, Space shows Quick Look for a threat file path, ⌫ quarantines or deletes with confirmation.
- Contrast: 4.5:1 minimum for text, checked in light, dark and Increase Contrast.
- Reduce Motion: the scan ring animation becomes a stepped fill. No pulsing.

### 1.5 False-positive handling (industry patterns)
Common good practice (Microsoft Defender, Malwarebytes, ESET, Objective-See): show **why** something was flagged, let users allowlist by hash, path, signer or Team ID, and submit to the vendor with one click. Bastion makes these first-class:
- **"Why was this flagged?"** panel on every detection: detection name, engine (signature / YARA rule / behavior / reputation), confidence, signer and notarization status, first-seen date, file hash, and the specific matched indicator (for example "Matched rule `MacStealer_Strings_v3`: 4 of 5 strings").
- **Allow** options with explicit scope: "This file only (hash)", "This app (Team ID ABC123XYZ)", "This folder". Each one is created as a visible rule, with an optional expiry.
- **Report false positive** sends a hash and metadata by default. Uploading the file sample is opt-in and needs a separate confirmation. You get a status back ("We reviewed this: the detection has been removed in definitions 2026.11.07").
- Restoring from quarantine always asks: "Restore and allow" or "Restore once".

### 1.6 Onboarding: permissions on macOS
- **Full Disk Access (FDA)** cannot be requested programmatically. The user must turn it on in System Settings › Privacy & Security › Full Disk Access. Deep link: `x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles`.
- **Endpoint Security system extension** needs approval: `OSSystemExtensionRequest`, then the user allows it in System Settings › General › Login Items & Extensions. On managed Macs, MDM can pre-approve.
- **Network Extension** (content filter / DNS proxy) brings its own "Allow" prompt.
- **Notifications**: `UNUserNotificationCenter.requestAuthorization`. Ask *in context*, after explaining why. Ask for `.timeSensitive` only for active threats.
- Best practice (LuLu, Little Snitch, Malwarebytes): one permission per step, an animated diagram of where to click, live detection (poll every 1 s) that ticks the step off automatically when access is granted, and a "Skip for now" option that leaves the dashboard showing a clear, non-scary "Limited protection" state.

---

## 2. Design principles

1. **Calm by default.** Silence means safe. Only interrupt for things that need a decision.
2. **Tell the truth.** No inflated counts. Tracking cookies are not "threats". Adware, PUPs and malware are labeled separately.
3. **Explain everything.** Every verdict has a "Why?" Every rule is readable as a sentence.
4. **One primary action per screen.**
5. **Native first.** System components, SF Symbols, Liquid Glass chrome only, standard window behavior.
6. **Never sell inside the product.**
7. **Fast.** Instant launch. Scans can be paused and resumed. Low impact on battery.

---

## 3. Information architecture

```
Window (NavigationSplitView, sidebar + detail)
├── Overview            ⌘1   (Dashboard)
├── Scan                ⌘2
├── Threats             ⌘3   (Detections + Quarantine segmented)
├── Network             ⌘4
├── Privacy & Posture   ⌘5
├── Activity            ⌘6   (event log / history)
└── Rules               ⌘7   (allowlist, blocklist, network rules)
Settings scene (⌘,)
MenuBarExtra (window style popover)
Notifications + in-app alert sheets
```

Sidebar footer (non-glass, small): protection status line ("Protected · Definitions updated 12 min ago").

---

## 4. Visual system (SwiftUI)

### 4.1 Color tokens
Use semantic system colors so dark mode and Increase Contrast work for free. Define tokens in an asset catalog with Any/Dark and High Contrast variants.

| Token | Meaning | SwiftUI value | Use |
|---|---|---|---|
| `bastion.accent` | Brand / interactive | Custom "Bastion Teal": light `#0A84A0`, dark `#40C8E0`. Set as `AccentColor` | Primary buttons, selection, links |
| `status.protected` | All good | `Color.green` (system) | Shield symbol, score ring 80–100 |
| `status.attention` | Recommendation, nothing urgent | `Color.yellow` (system); text uses `.primary`, not yellow | Score 50–79, posture items |
| `status.action` | Active threat / protection off | `Color.red` (system) | Only for live detections or protection disabled |
| `status.info` | Neutral info | `Color.blue` (system) | Updates, tips |
| `status.quarantined` | Contained | `Color.secondary` / `.gray` | Quarantined items show as safe and contained, not red |
| Surfaces | Content backgrounds | `Color(nsColor: .windowBackgroundColor)`, `.controlBackgroundColor`; `.background(.background.secondary)` for cards | Cards and lists. **No glass on content.** |
| Text | | `.primary`, `.secondary`, `.tertiary` | Never hard-code black or white |

Rules:
- Red appears on screen **only** while there is an unresolved detection or a disabled core protection.
- Status tint goes on the *symbol*. Body text stays `.primary` for contrast.
- Card style: `.background(.background.secondary, in: .rect(cornerRadius: 12, style: .continuous))`, or `ContainerRelativeShape` inside containers. No drop shadows in dark mode.
- Liquid Glass: only the sidebar, toolbar, floating scan-control bar (`.glassEffect(.regular.interactive())`), and the menu bar popover chrome. The primary toolbar button uses `.buttonStyle(.glassProminent)`. Secondary actions use `.buttonStyle(.glass)`.

### 4.2 Typography
System font (SF Pro) only. Use text styles, never `.system(size:)` except in the score numeral.

| Role | SwiftUI |
|---|---|
| Screen title | Toolbar/navigation title (system) |
| Hero status ("Your Mac is protected") | `.font(.largeTitle).fontWeight(.semibold)` |
| Score numeral | `.font(.system(size: 56, weight: .semibold, design: .rounded)).monospacedDigit()`; scales with the app's text-size setting |
| Section header | `.font(.headline)` |
| Card title | `.font(.title3).fontWeight(.medium)` |
| Body | `.font(.body)` |
| Metadata (paths, hashes, times) | `.font(.callout).foregroundStyle(.secondary)`; hashes and paths use `.monospaced()` and `.textSelection(.enabled)` |
| Counters during scan | `.monospacedDigit()` so numbers don't jitter |

Spacing scale: 4 / 8 / 12 / 16 / 24 / 32. Detail-view content max width 880 pt, centered. Minimum window 900×600. Sidebar width 200–260.

### 4.3 Motion
- Use `.contentTransition(.numericText())` for counters and `.symbolEffect(.bounce)` once when a scan finishes clean.
- The scan ring rotates with a gentle gradient. Under Reduce Motion it becomes a static determinate ring.
- No shaking, flashing or pulsing red, ever.

### 4.4 App icon
A shield-and-tower silhouette in the Bastion teal, built as layered Icon Composer artwork so it renders correctly in Liquid Glass (clear, tinted and dark variants).

---

## 5. SF Symbols map

| Feature | Symbol | Notes |
|---|---|---|
| App / Overview | `shield.lefthalf.filled` | Sidebar icon |
| Protected state | `checkmark.shield.fill` | Green, hierarchical |
| Attention state | `exclamationmark.shield.fill` | Yellow |
| Action needed | `xmark.shield.fill` | Red, only for an active threat or protection off |
| Protection paused | `pause.circle.fill` (overlay) / `shield.slash` | Secondary color |
| Scan | `magnifyingglass` / during scan `arrow.trianglehead.2.clockwise.rotate.90` with `.symbolEffect(.rotate)` | |
| Quick scan | `bolt` | |
| Full scan | `internaldrive` | |
| Custom scan | `folder.badge.gearshape` | |
| Threats | `ladybug` | Neutral, not a skull |
| Quarantine | `archivebox` (contents) / `lock.square.stack` | |
| Restore | `arrow.uturn.backward` | |
| Delete | `trash` | |
| Allow / trust | `checkmark.seal` | |
| Report false positive | `flag` | |
| Why / explain | `info.circle` / `questionmark.bubble` | |
| Network | `network` | |
| Firewall / blocked connection | `hand.raised` | |
| Allowed connection | `arrow.up.right.circle` | |
| DNS / web protection | `globe.badge.chevron.backward` (fallback `globe`) | |
| Wi-Fi security | `wifi.exclamationmark` / `wifi` | |
| Privacy & Posture | `hand.raised.square` | Sidebar |
| Camera / mic access | `video`, `mic` | |
| Login items / persistence | `power` / `gearshape.2` | |
| FileVault | `lock.laptopcomputer` | |
| Firewall (macOS) | `flame` → prefer `shield.checkered` (avoid flame) | |
| Gatekeeper / SIP | `checkmark.shield` | |
| Software updates | `arrow.down.circle` | |
| Activity log | `clock.arrow.circlepath` | |
| Rules | `list.bullet.rectangle` | |
| Settings | `gearshape` | |
| Menu bar extra | `shield.lefthalf.filled` (template); during scan `shield.lefthalf.filled` + `.symbolEffect(.pulse)` only if Reduce Motion is off; threat state `exclamationmark.shield` | Must be a monochrome template |
| Ransomware guard | `folder.badge.minus` / `lock.doc` | |
| USB / external | `externaldrive` | |
| Definitions | `arrow.triangle.2.circlepath` | |

Use `.symbolRenderingMode(.hierarchical)` for status symbols and `.monochrome` in the menu bar. Check every symbol's availability against the minimum OS in Xcode's SF Symbols app.

---

## 6. Screen-by-screen spec

### 6.1 Overview (Dashboard)
**Purpose:** answer "Am I OK?" in under a second.

Layout (top to bottom):
1. **Hero status card** (full width)
   - Left: large status symbol (64 pt) and hero line.
   - Right: **Security Score ring** (120 pt). It is a `Gauge` with `.gaugeStyle(.accessoryCircularCapacity)` scaled, or a custom `Circle().trim` with the score numeral.
   - Below: one line of detail and one primary button.
2. **Three status tiles** (`Grid`, 3 columns, collapsing to 1 column under 700 pt):
   - Real-time protection: On/Off, with an inline `Toggle` that needs confirmation to turn off.
   - Last scan: "Today, 9:14 · No threats found" plus a "Scan Now" link.
   - Definitions: "Up to date · 12 min ago".
3. **Recommendations list** (max 3, then "See all in Privacy & Posture"). Each row: symbol, title, one-line reason, a "Fix" button, and a dismiss (×) that offers "Ignore this recommendation".
4. **Recent activity** (last 5 events, "Show all" goes to Activity).

States:
| State | Symbol | Hero copy | Detail | Primary button |
|---|---|---|---|---|
| Protected | `checkmark.shield.fill` green | "Your Mac is protected" | "Real-time protection is on. Last scan found nothing." | "Run Quick Scan" (secondary style) |
| Recommendations | `exclamationmark.shield.fill` yellow | "Your Mac is protected" | "2 settings could make it more secure." | "Review" |
| Threat found | `xmark.shield.fill` red | "1 item needs your attention" | "Bastion blocked it from running. Choose what to do next." | "Review Item" (prominent) |
| Protection off | `shield.slash` red | "Real-time protection is off" | "Files aren't being checked as they open." | "Turn On" |
| Limited (missing FDA) | `exclamationmark.shield.fill` yellow | "Protection is limited" | "Bastion can't check some folders without Full Disk Access." | "Grant Access…" |
| Paused (user) | `pause.circle.fill` secondary | "Protection paused" | "Resumes automatically at 3:40 PM." | "Resume Now" |

**Security Score** (0–100, honest and fixable):
- What counts (weights shown in a "How is this calculated?" popover):
  - Real-time protection on (25), definitions current under 24 h (10), Full Disk Access granted (10), no unresolved detections (20), FileVault on (10), macOS firewall on (5), automatic macOS updates on (5), Gatekeeper and SIP on (10), no unknown login items or launch agents (5).
- Labels: 90–100 "Excellent", 75–89 "Good", 50–74 "Fair", under 50 "Needs attention". Never "Poor", "Danger" or "At risk".
- Every lost point links to its fix. Points never depend on buying anything.
- The ring color follows the label (green / green / yellow / red). The label text always appears next to the ring.

Toolbar: title "Overview". Trailing: a `ToolbarItem` showing the "Quick Scan" button with `.glassProminent`. The status text item has no glass backing.

### 6.2 Scan
**Idle layout:**
- A segmented-style choice of three large cards (`LazyVGrid`, selectable):
  - **Quick Scan** (`bolt`): "Checks the places malware usually hides. About 1 minute."
  - **Full Scan** (`internaldrive`): "Checks every file on your Mac. Can take 20 minutes or more."
  - **Custom Scan** (`folder.badge.gearshape`): "Choose files, folders or drives." It also accepts drag-and-drop onto the card and onto the Dock icon.
- Primary button: "Start Scan".
- Below: "Scheduled scans: Quick Scan daily at 12:00 · Edit…" and the history of the last 5 scans.

**Running layout:**
- Large determinate ring with percentage. For a Full Scan, show an indeterminate ring until the file count is estimated (under 2 s), then switch to determinate.
- Under the ring: "Scanning… 42,318 of 118,904 files" (`.monospacedDigit()`), a currently scanned path truncated in the middle (`.truncationMode(.middle)`, secondary, updated at most 5×/s), elapsed and estimated remaining time ("About 6 minutes left"), and an items-found counter that shows "0 items found" in secondary, never red until the scan ends.
- Floating glass control bar at the bottom: "Pause", "Stop", and a "Low impact" toggle (`tortoise` symbol) that lowers I/O priority.
- The scan continues if the window closes. The menu bar shows progress.

**Results layout:**
- Clean: `checkmark.shield.fill` with one bounce. "No threats found" / "Scanned 118,904 files in 7 min 12 s." Buttons: "Done", "View Report".
- Findings: "Found 2 items" / "They've been moved to quarantine and can't run." The list of findings follows (same rows as Threats). Button: "Review Items".
- Errors or skipped files: an expandable disclosure "312 files couldn't be scanned (permission denied or in use). Why?"

### 6.3 Threats (Detections + Quarantine)
The toolbar has a segmented `Picker`: **Detections** | **Quarantine** | **Allowed**.

Detections table (`Table`, sortable):
| Column | Content |
|---|---|
| Item | App/file icon (`NSWorkspace.icon(forFile:)`), name, path (secondary, middle-truncated) |
| Type | Badge: "Malware", "Adware", "Potentially unwanted", "Suspicious behavior" |
| Severity | Text with symbol: "High" / "Medium" / "Low". Color is limited to the symbol |
| Status | "Quarantined", "Blocked", "Needs decision" |
| Detected | Relative date |

Selecting a row opens an **Inspector** (`.inspector(isPresented:)`, which gets Liquid Glass automatically):
- Header: icon, name, type badge.
- **"Why was this flagged?"** section (always expanded on first view):
  - "Detected as **OSX.AMOS.Stealer** by **behavior monitoring**."
  - "It tried to read saved browser passwords and send them to an unknown server (185.x.x.x)."
  - Evidence list: matched rule or signature, behavior events with timestamps, code signature ("Not signed" / "Signed by Developer ID: Acme Corp (TEAMID)" / "Notarized: No"), first seen, prevalence ("Seen on fewer than 10 Macs"), SHA-256 (copyable).
  - Confidence: "High confidence" / "Medium confidence: may be a false positive".
- **What we did:** "Moved to quarantine on Nov 5, 9:14 AM. The file is encrypted and can't run."
- Actions (bottom, glass bar): **Delete** (destructive, confirmation), **Restore…**, **Allow…**, **Report as Safe…**, and "Show in Finder" (disabled while quarantined; offers to show the original location instead).
- Links: "Look up on VirusTotal" (opens the browser with the hash only, never uploads), "Copy details".

Quarantine view: the same table, with columns for original location, date, size, and auto-delete date ("Deleted automatically after 30 days. Change in Settings."). Multi-select allows Delete / Restore. Empty state: `archivebox` with "Quarantine is empty" / "Files Bastion isolates will appear here. They can't run while they're here."

Allowed view: lists allowlist entries with scope, created date, expiry, and a "Remove" button. This mirrors Rules but is limited to file allowances.

Restore sheet:
- Title: "Restore "Example.app"?"
- Body: "Bastion flagged this as Adware (medium confidence). Restore it only if you trust where it came from."
- Options (radio): "Restore and always allow this file", "Restore and allow everything from this developer (Acme Corp)", "Restore once (scan again next time)".
- Buttons: "Cancel" (default), "Restore".

Report sheet:
- Title: "Report as safe"
- Body: "We'll send the file's fingerprint and detection details to the Bastion lab. We won't send the file itself unless you choose to."
- Checkbox (off by default): "Include the file to help us review it faster".
- Optional text field: "Anything we should know? (optional)"
- Buttons: "Cancel", "Send Report".
- Afterwards: "Thanks — we'll review this within 2 business days. You'll get a notification when we're done."

### 6.4 Network
Segments: **Connections** | **Rules** | **Web Protection**.

- **Connections:** a live list grouped by app (`OutlineGroup`). Rows show the app icon, name, connection count, data sent and received (sparkline), and whether it is allowed or blocked. Expand to see destinations (domain, country flag emoji not allowed; use the country code text, port, protocol). Filter field and "Only show blocked" toggle.
- **Rules:** human-readable sentences: "**Safari** can connect to **any server**", "**UpdaterHelper** is blocked from **ads.example.com**". Edit with a sheet using `Picker`s.
- **Web Protection:** toggle for "Block known malicious and phishing sites", optional "Block trackers" (off by default, labeled "Privacy, not security"), and a counter: "Blocked 14 dangerous sites this month".
- Wi-Fi card at the top: "Connected to **HomeNet** · WPA3 · No issues found" or "This network doesn't use encryption. Avoid entering passwords until you're on a trusted network."
- Firewall mode picker (Settings, mirrored here): "Silent (recommended): learn automatically, block known-bad", "Ask me for new apps", "Block all new apps".
- First 48 hours: learning mode with no prompts. Afterwards, the banner says "Bastion learned how 37 apps use the network. Review".

### 6.5 Privacy & Posture
A checklist of Mac security settings, grouped. Each row: symbol, title, status, short reason, and "Fix" or "Open Settings".

Groups:
- **macOS protections:** FileVault, Firewall, Gatekeeper, System Integrity Protection, automatic updates, Lockdown Mode (info only, never recommended by default).
- **Startup & background:** login items and launch agents/daemons (KnockKnock/BlockBlock-style list), new persistence items flagged with "New" badges. Each row has "Allow", "Disable" (reversible), and "Why?".
- **App permissions:** which apps have Camera, Microphone, Screen Recording, Accessibility, Full Disk Access, and Input Monitoring. Unusual ones are highlighted ("**FreeConverter** can record your screen. Was this intended?").
- **Live privacy indicators:** "Camera in use by FaceTime" (real time, from Endpoint Security / AV capture).
- **Accounts & passwords:** optional breach check (k-anonymity, opt-in) and a link to the macOS Passwords app.
- **Ransomware guard:** list of protected folders (Documents, Desktop, Pictures by default) with "Add Folder…".

Ignored items go to a collapsed "Ignored (2)" section. Ignoring restores the score points? **No.** It removes the item from the score with a note: "Ignored items don't count toward your score."

### 6.6 Activity
A filterable log (`Table`): time, category symbol, event ("Blocked connection from UpdaterHelper to ads.example.com"), and outcome. Filters: All / Threats / Network / Scans / Updates / Settings changes. Exporting to CSV or JSON is available for power users. Retention: 90 days (configurable).

### 6.7 Rules
A single place for all user decisions: file allowlist, file blocklist, network rules, persistence allowances, and alert "don't ask again" decisions. Each is a sentence, with source ("You, Nov 3", "Your organization", "Bastion default"), expiry and toggle. Search. Import/export as `.bastionrules` (JSON).

### 6.8 Settings (`Settings` scene, `TabView`, sidebar style on macOS 26)
Tabs and controls:

**General**
- Launch Bastion at login (on)
- Show in menu bar (on)
- Show Dock icon (on; when off, the app becomes menu-bar-only via `NSApp.setActivationPolicy(.accessory)`)
- Text size: Default / Large / Larger
- Language (system default)

**Protection**
- Real-time protection (on). Turning it off asks for a duration: 15 min / 1 hour / until restart / until I turn it on.
- Scan on file open, on download, on USB/external mount (on)
- Behavior monitoring (on)
- Ransomware guard (on)
- Detect potentially unwanted programs (PUPs) (on) and adware (on)
- Scan inside archives (on) / Max archive depth
- Exclusions… (folders, extensions, processes), with a warning: "Excluded items aren't checked. Only exclude things you trust."
- Quarantine: auto-delete after 7 / 30 / 90 days / never (30)

**Scans**
- Scheduled scan: off / daily / weekly; type; time
- Pause scans on battery (on)
- Pause during Low Power Mode (on)
- Pause while on a video call or in full-screen (on)
- Scan priority: Low impact / Balanced / Fast

**Network**
- Firewall mode (Silent / Ask / Block new)
- Web protection (on), tracker blocking (off)
- Wi-Fi checks (on)

**Notifications**
- Per category: Threats (always on; can only be set to banner vs. alert), Scan finished (off), Blocked connections (off), Weekly summary (on), Updates (off), Recommendations (weekly digest)
- Quiet Mode: follow macOS Focus (on); quiet during full-screen apps (on)
- Sounds (off)

**Updates**
- Update definitions automatically (on, hourly)
- Update the app automatically (on)
- Beta channel (off)
- "Check Now" button with last-checked time

**Privacy**
- Send anonymous usage statistics (**off** by default)
- Send crash reports (ask)
- Cloud reputation lookups (on; sends hashes only, explained)
- Automatically submit samples of new threats (off)
- "View what we send" link that opens a local log of outbound telemetry

**Account**
- Plan, renewal date, devices. "Manage Subscription" links to the App Store or the web portal. "Turn Off Auto-Renew" link. No upsell banners.

**Advanced**
- Admin password required to disable protection (off; on for managed Macs)
- Lock settings with Touch ID (off)
- Logs: open folder, export diagnostics
- Reset all rules (destructive, confirmation)
- Uninstall Bastion… (a clean, guided uninstaller that removes the system extension too; no guilt-trip screens)

### 6.9 Menu bar popover (`MenuBarExtra`, `.window` style, 320 pt wide)
```
┌───────────────────────────────┐
│ ✓ Your Mac is protected       │  status symbol + line
│   Score 92 · Excellent        │
├───────────────────────────────┤
│ [ Quick Scan ]  [ Open Bastion ]│ glass buttons
├───────────────────────────────┤
│ Last scan  Today 9:14 · Clean │
│ Definitions  12 min ago       │
│ Network  3 blocked today      │
├───────────────────────────────┤
│ Pause Protection ▸  (15m/1h/…)│
│ Settings…           ⌘,        │
│ Quit Bastion                  │
└───────────────────────────────┘
```
- During a scan, the top section is replaced by a progress bar, "Quick Scan · 64%", and Pause/Stop.
- When a threat is present, the top shows "1 item needs your attention" and a "Review" button. The menu bar icon becomes `exclamationmark.shield` (template; macOS colors it). No badges, counters or animations in the menu bar during normal operation.
- "Quit Bastion" explains: "Real-time protection keeps running in the background. To stop it, turn off protection in Settings." (The system extension runs separately from the UI.)

### 6.10 Alerts and notifications
Severity ladder (strict):

| Level | Trigger | Surface | Interruption |
|---|---|---|---|
| Critical | Active malware blocked or quarantined, ransomware behavior stopped | `UNNotification` with `.timeSensitive` + red state in the app and menu bar | Banner; alert style only if the user chose it |
| Decision | Firewall "Ask" mode for a new app; new persistence item from an unsigned app | Floating panel (`NSPanel`, non-activating, top-right) with a 60 s timeout → default safe action ("Block until I decide") | One at a time; queued |
| Info | Scan finished, definitions updated, weekly summary | Notification, off by default except the weekly summary | Passive |
| Silent | Known-good allowed, tracker blocked | Activity log only | None |

Rate limits: at most 1 non-critical notification per hour. Group by thread (`threadIdentifier` per category). After 3 identical decisions, offer to make a rule.

Decision panel layout (LuLu-inspired, modernized):
- App icon + "**UpdaterHelper** wants to connect to **telemetry.example.com**"
- Details disclosure: process path, signer ("Signed by Example Inc. · Notarized"), port and protocol, parent process, VirusTotal link.
- Buttons: "Block" / "Allow". Scope picker: "Once / Until app quits / Always". Default: "Always".
- Checkbox: "Apply to all connections from this app".

Notification actions (`UNNotificationCategory`): "Review" (opens Threats), "Delete" (destructive, with authentication if required), "Allow…" (opens the app; never allow straight from a notification).

---

## 7. Copy guide and key strings

Voice: calm, specific, short, second person, plain verbs. Say what happened, what Bastion already did, and what (if anything) the user should do.

Banned words and patterns: "DANGER", "WARNING!", "infected", "at risk", "your Mac is vulnerable", "act now", "critical threat detected!!", all-caps, exclamation marks in status text, countdown timers that pressure, "You're unprotected without Premium", confirm-shaming ("No, I don't care about my security").

| Key | String |
|---|---|
| `status.protected.title` | Your Mac is protected |
| `status.protected.detail` | Real-time protection is on. Last scan found nothing. |
| `status.recommendations.detail` | %d settings could make your Mac more secure. |
| `status.threat.title` | %d item needs your attention / %d items need your attention |
| `status.threat.detail` | Bastion blocked it from running. Choose what to do next. |
| `status.off.title` | Real-time protection is off |
| `status.off.detail` | Files aren't being checked as they open. |
| `status.limited.title` | Protection is limited |
| `status.limited.detail` | Bastion can't check some folders without Full Disk Access. |
| `status.paused.title` | Protection paused |
| `status.paused.detail` | Resumes automatically at %@. |
| `score.label.excellent / good / fair / attention` | Excellent / Good / Fair / Needs attention |
| `score.explain` | Your score reflects settings you can change on this Mac. It never depends on what you've bought. |
| `scan.quick.desc` | Checks the places malware usually hides. About 1 minute. |
| `scan.full.desc` | Checks every file on your Mac. Can take 20 minutes or more. |
| `scan.custom.desc` | Choose files, folders or drives to check. |
| `scan.progress` | Scanning… %@ of %@ files |
| `scan.eta` | About %@ left |
| `scan.clean.title` | No threats found |
| `scan.clean.detail` | Scanned %@ files in %@. |
| `scan.found.title` | Found %d item / Found %d items |
| `scan.found.detail` | They've been moved to quarantine and can't run. |
| `scan.skipped` | %d files couldn't be scanned. Why? |
| `threat.why.header` | Why was this flagged? |
| `threat.confidence.medium` | Medium confidence: this may be a false positive. |
| `threat.action.done` | Moved to quarantine on %@. The file is encrypted and can't run. |
| `quarantine.empty.title` | Quarantine is empty |
| `quarantine.empty.detail` | Files Bastion isolates will appear here. They can't run while they're here. |
| `restore.title` | Restore "%@"? |
| `restore.body` | Bastion flagged this as %@ (%@ confidence). Restore it only if you trust where it came from. |
| `delete.confirm.title` | Delete "%@" permanently? |
| `delete.confirm.body` | This can't be undone. |
| `report.title` | Report as safe |
| `report.body` | We'll send the file's fingerprint and detection details to the Bastion lab. We won't send the file itself unless you choose to. |
| `report.thanks` | Thanks — we'll review this within 2 business days. |
| `notif.threat.title` | Bastion blocked a threat |
| `notif.threat.body` | "%@" was moved to quarantine. No action needed unless you recognize it. |
| `notif.ransom.title` | Bastion stopped suspicious file changes |
| `notif.ransom.body` | "%@" started encrypting files in Documents. It's been stopped and %d files were restored. |
| `notif.weekly.title` | Your week with Bastion |
| `notif.weekly.body` | Checked %@ files, blocked %d connections. Nothing needs your attention. |
| `notif.fp.resolved` | We reviewed "%@". It's safe, and the detection has been removed. |
| `network.unencrypted` | This network doesn't use encryption. Avoid entering passwords until you're on a trusted network. |
| `network.ask.title` | %@ wants to connect to %@ |
| `protection.off.confirm.title` | Turn off real-time protection? |
| `protection.off.confirm.body` | Files won't be checked as they open. Choose how long: |
| `quit.info` | Real-time protection keeps running in the background. To stop it, turn off protection in Settings. |
| `exclusion.warning` | Excluded items aren't checked. Only exclude things you trust. |
| `uninstall.title` | Uninstall Bastion |
| `uninstall.body` | This removes the app, its background protection and your rules. Quarantined files will be deleted. |

---

## 8. Onboarding flow

A single window (640×520), no sidebar, Liquid Glass page indicator. Progress: "Step 2 of 5". "Skip for now" on every permission step. Re-entry from the Dashboard "Limited" card.

1. **Welcome**
   - Symbol: `shield.lefthalf.filled` (animated draw-on, unless Reduce Motion)
   - Title: "Welcome to Bastion"
   - Body: "Bastion protects your Mac quietly in the background. We'll set up three permissions, then run a quick check. It takes about 2 minutes."
   - Small print: "No ads. No upsells. Your files stay on your Mac."
   - Button: "Get Started"

2. **Install background protection (system extension)**
   - Title: "Turn on background protection"
   - Body: "This lets Bastion check files as they open and stop malware before it runs. macOS will ask you to allow it."
   - Button: "Continue". This triggers `OSSystemExtensionRequest`.
   - Then an inline animated diagram: "Open System Settings › General › Login Items & Extensions, then turn on **Bastion Security Extension**." Button: "Open System Settings".
   - Live check: poll the extension state. On success, a green check and "Background protection is on", then auto-advance after 1 s.
   - Admin password note: "macOS may ask for your password. Bastion never sees it."

3. **Full Disk Access**
   - Title: "Let Bastion check every folder"
   - Body: "macOS keeps some folders, like Mail and Messages, private by default. Full Disk Access lets Bastion scan them for threats. Bastion only checks files for malware; it doesn't read or upload your content."
   - Button: "Open Privacy Settings" (deep link `x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles`)
   - Side-by-side mini window: an animated screenshot showing the Bastion toggle being turned on. Optional: a draggable app icon tile ("Drag Bastion here if it isn't listed").
   - Live detection: try reading a TCC-protected path (for example `~/Library/Safari/Bookmarks.plist`) every 1 s. On success: "Full Disk Access is on".
   - If macOS requires a restart of the app: "macOS needs Bastion to restart to finish. Restart Now / Later".

4. **Network protection (optional)**
   - Title: "Block dangerous websites and connections"
   - Body: "Bastion can stop apps and websites from reaching known-malicious servers. macOS will ask you to allow a network filter."
   - Buttons: "Turn On" / "Not Now"
   - Mode choice (small): "Silent: Bastion decides for you (recommended)" / "Ask me about new apps".

5. **Notifications**
   - Title: "Hear from us only when it matters"
   - Body: "We'll notify you if Bastion blocks a threat. Everything else stays in the app. You can change this anytime."
   - Preview of an example notification (rendered).
   - Button: "Allow Notifications" (calls `requestAuthorization([.alert, .sound, .badge, .timeSensitive])`), "Not Now".

6. **First scan**
   - Title: "Let's do a quick check"
   - Auto-starts a Quick Scan with a compact ring. "This takes about a minute. You can close this window — the scan continues."
   - Result: "All set. Your Mac is protected." Score shown with a gentle reveal. Button: "Open Bastion".
   - If something is found: "Found 1 item. It's in quarantine and can't run." Button: "Review".

Post-onboarding:
- The menu bar icon appears with a one-time coach mark: "Bastion lives here. Click for status and quick scans."
- No email capture, no rating prompts during the first 14 days, and never after a threat alert.

Managed Macs (MDM): if a configuration profile pre-approves the extension and FDA, skip steps 2–4 and show "Your organization has set up Bastion."

---

## 9. Performance and engineering notes for UI
- The UI app is separate from the system extension and talks to it over XPC. The UI can quit with no loss of protection.
- Dashboard data comes from a cached snapshot so it renders instantly. Live values stream in afterwards.
- Throttle scan progress UI updates to 10 Hz, and path labels to 5 Hz.
- Use `@Observable` view models, `Table` for long lists (lazy), and avoid `GeometryReader` in rows.
- Snapshot tests across light, dark, Increase Contrast, Reduce Transparency, and the three text sizes.
- Localize with String Catalogs (`.xcstrings`) using the keys in section 7. Use plural variants for counts.

---

## 10. Anti-pattern checklist (release gate)
- [ ] No promotional content anywhere except Settings › Account
- [ ] No red when no action is needed
- [ ] Every alert type can be turned off or quieted, except active-threat alerts, which can be downgraded to banners
- [ ] Every "don't ask again" creates a visible, editable rule
- [ ] Every detection has a "Why?" panel and a false-positive path
- [ ] Score never references paid features
- [ ] Uninstall works from inside the app with no guilt-trip screens
- [ ] VoiceOver walkthrough of onboarding, Dashboard, Threats passes
- [ ] All strings pass the banned-words lint

---

## Sources
- [Norton Community: Is Norton 360 a marketing program?](https://community.norton.com/t/is-norton-360-a-marketing-program-all-it-does-is-try-to-sell-me-stuff-most-of-which-i-already-own/354213)
- [Norton Community: tired of being hustled for more junk](https://community.norton.com/t/norton-360-tired-of-being-hustled-for-more-junk/244948)
- [Norton Community: harassing me daily to order more security apps](https://community.norton.com/t/norton-360-is-harassing-me-daily-to-order-more-security-apps/378212)
- [Norton Community: repeated messages about rapportd/sharingd](https://community.norton.com/t/annoying-repeated-norton-security-messages-about-access-to-rapportd-sharingd/214791?page=2)
- [Norton Community: Norton 360 update stinks](https://community.norton.com/t/norton-360-update-stinks/254170)
- [Norton Community: Popups on MacBook Pro](https://community.norton.com/t/popups-on-macbook-pro/218281)
- [checkthat.ai: Norton reviews 2026](https://checkthat.ai/brands/norton/reviews)
- [Apple Discussions thread](https://discussions.apple.com/thread/255533005)
- [WWDC25 session 310: Build an AppKit app with the new design](https://developer.apple.com/videos/play/wwdc2025/310/)
- [Cult of Mac: Liquid Glass changes in iOS 27 / macOS 27](https://www.cultofmac.com/news/liquid-glass-changes-ios-27-macos-27)
- [Macworld: Malwarebytes Premium review](https://www.macworld.com/article/3394306/malwarebytes-premium-review-a-fast-efficient-security-program-with-an-unusual-approach.html)
- [Beebom: Malwarebytes for Mac review](https://beebom.com/malwarebytes-mac-review/amp/)
- [Malwarebytes forum: menubar / greedy UI design feedback](https://forums.malwarebytes.com/topic/310777-issue-feedback-cant-start-scan-from-menubar-greedy-ui-design/)
- [Help Net Security: LuLu product showcase](https://www.helpnetsecurity.com/2026/04/27/product-showcase-lulu-macos-firewall/)
- [Nektony: LuLu vs Firewally](https://nektony.com/reviews/lulu-vs-firewally)
- Apple Human Interface Guidelines (Designing for macOS, Menu bar extras, Settings, Notifications, SF Symbols, Accessibility); "Adopting Liquid Glass" documentation. These were not fetched directly in this pass, so check them against the current HIG before implementation.
