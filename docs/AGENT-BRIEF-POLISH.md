# Brief for polish agents (2026-11-07)

Project: RamPart, a macOS antivirus at /Users/arankeyhan/Rampart. Read ARCHITECTURE.md (especially the ZERO POP-UPS RULE and the SwiftUI notes) and Sources/RampartApp/Design.swift + Theme.swift + BrandMark.swift before editing.

The user asked for "subtle changes … around the app" that make it feel thoughtful and premium, in the spirit of a drag-to-Applications install window: small, delightful, useful touches. Examples: helpful inline hints, better empty states, hover states, smooth transitions, clear progress, undo for destructive actions, keyboard shortcuts, contextual menus, copy buttons, tooltips, sensible defaults, friendlier wording, polished spacing and alignment. Keep the calm, honest tone. No fear-mongering, no upsells, no fake data.

Hard rules
- Edit ONLY the files you own (listed in your task). New files are allowed only where your task says so. If you need a change elsewhere, write the exact one-line hook in your final report; the lead will add it.
- 40 agents work at once. NEVER run `swift build` directly. Build ONLY with `scripts/agent-build.sh` (it serialises builds). If the build fails in a file you don't own, ignore that error and retry later; don't touch that file.
- `@State` doesn't compile here: use `@StateVar` (typealias). No `#Preview`, no `@Entry`.
- ZERO POP-UPS: never launch the app, open anything, take screenshots, run osascript or sudo, touch the pasteboard or keychain, or show any window on screen. Verify by building only.
- Respect Reduce Motion and Reduce Transparency, keep VoiceOver labels, and keep idle CPU low (animations only while visible and finite).
- Use `Product.name` ("RamPart") for the product name in UI text.
- Don't commit. Keep your final report short: what you changed (bullets), any hook lines for the lead, and the build result.
