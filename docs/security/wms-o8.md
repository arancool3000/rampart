# WMS o8: the app process and the Refresh cleaner (2026-11)

Owned area: `Sources/RampartApp` (untrusted-string rendering, notification actions, URL schemes / Apple Events,
Desktop Mode launcher and search, Bot window, drag and drop, PermissionGuidePanel) and `Sources/RampartRefresh`
(cleaner, `RefreshSafetyPolicy`, undo). Regression suite: `wmso8` (`Sources/rampart-selftest/SelfTest+WMSo8.swift`).

## Threat model
- Attacker controls strings RamPart shows: file names, process and app names, SSIDs, web titles, AI output,
  Cat & Mouse alert text, and `.app` bundles dropped into `~/Applications` (user-writable) or `/Applications`.
- Same-user malware can create, rename and symlink files in the home folder at any time, including during a
  Refresh clean, can edit `undo.json`, and can replace `/opt/homebrew/bin/brew` output.
- Goal of the attacker: make RamPart itself the confused deputy (trash or permanently delete documents,
  RamPart data, decoys or cloud files; launch a planted app; show a fake "All clear").

## Findings

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| O8-1 | High | Refresh cleaner trusted the item's category: a `.homebrew` item from a tampered `brew cleanup -n` (or any forged item) pointing at `~/Documents/x` was trashed (Homebrew is "safe" risk, pre-selected). | Fixed: per-category allowlist `RefreshSafetyPolicy.categoryRefusal`, enforced in scanner, preview, clean and again on the verified path at move time. |
| O8-2 | High | TOCTOU: the policy checked a path, then `trashItem` re-resolved it. Swapping a cache folder for a symlink to `~/Documents` between check and move redirected the move. | Fixed: `SecureTrash` opens the folder chain with `O_NOFOLLOW`, pins device+inode, re-runs the policy on the verified path, re-checks folder path (`F_GETPATH`) and item identity, then `renameatx_np(RENAME_EXCL)` relative to the verified folder fd. |
| O8-3 | High | "Empty Trash" followed a symlinked `~/.Trash` (e.g. to `~/Documents`) and permanently deleted its contents. | Fixed: refuses unless the Trash is a real directory (`notATrashFolder`). |
| O8-4 | Medium | Undo trusted `undo.json`: a tampered entry could "restore" `~/Documents/x` to any path. | Fixed: `undoAllowed` requires the source inside a Trash folder and the destination to pass the path rules; restoring through a symlinked parent is refused. |
| O8-5 | Medium | Path rules were case-sensitive; on case-insensitive APFS `~/documents`, `~/library/mobile documents/...`, `.../application support/RAMPART` slipped past lexical checks (realpath usually caught it at clean time, the scanner did not). | Fixed: all lexical comparisons case-insensitive. |
| O8-6 | Medium | Cloud files: only iCloud Drive paths were refused. Other File Provider folders (`~/Library/CloudStorage/*`), dataless placeholders and `.name.icloud` stubs could be trashed, which deletes them in the cloud. | Fixed: `CloudStorage` refused, `SF_DATALESS` and `.icloud` stubs refused (`cloudPlaceholder`), also inside folders (bounded walk). |
| O8-7 | Medium | Decoys: when the Cat & Mouse status hadn't loaded, Refresh ran with no decoy list. | Fixed: `fallbackDecoyPaths` (on-disk registry + maze root) when no live list. |
| O8-8 | Low | A symlink item was allowed without checking its parent's real location. | Fixed: parent resolved and re-checked. |
| O8-9 | Medium | Desktop launcher listed planted look-alikes (`~/Applications/Safari.app` with another bundle ID, Cyrillic "Sуstem Settings", a fake "RamPart"), symlinked `.app`s pointing anywhere, raw bidi/newline names; a `/Applications` app reusing an Apple bundle ID won the tie over `/System`. | Fixed: skeleton-based look-alike filter, symlinked bundles only if they resolve into an app folder, names via `SafeText`, `/System/Applications` scanned first, click-time `stillSame` re-check (bundle ID, location), drops limited to listed apps. |
| O8-10 | Low | Untrusted names reached a confirmation dialog raw (Threats "Delete … permanently?", Vault "Delete …?"); `QuarantineText` missed U+2028/2029, zero-width and tag chars; Cat & Mouse and Camera/Mic notification title/body unsanitised; camera/mic badge app names raw. | Fixed: all via `SafeText`; `Notifier.post` also cleans title/body as defence in depth. |

Checked and found sound: no URL scheme (`CFBundleURLTypes`) and no scripting dictionary, so Apple Events reach only
the standard suite; `odoc` only starts a bounded custom scan (hx8). Notification responses can only come from
RamPart's own notifications (per-bundle `UNUserNotificationCenter`); "Stay connected" needs the per-notification
token; "Restore internet" goes through the Touch-ID kill-switch flow. The reveal distributed notification is
rate-limited (hx8). AI/bot output is rendered with `Text(verbatim:)` and `SafeText`; no Markdown or link
rendering of untrusted text was found.

## Residual risks
- Same-user malware can delete files itself; Refresh guarantees only that RamPart is not the tool. A file can still
  be swapped inside the verified folder in the microseconds between the identity re-check and `renameat`; at worst
  that moves an attacker-placed object (a hard link or a folder the attacker moved there itself).
- When `~/.Trash` can't be written directly (other volume, privacy rules) the move falls back to
  `FileManager.trashItem` after an identity + realpath re-check: a narrower but path-based window.
- Look-alike detection covers a fixed list of well-known apps plus everything in `/System`. A planted app with a
  novel name is still listed; Gatekeeper/quarantine and RamPart's Download Gate cover first launch. Ad-hoc signing
  means RamPart can't pin its own Developer ID for the "RamPart" check, so it checks the bundle ID only.
- No Endpoint Security AUTH: RamPart can't block an app launched from Finder.
