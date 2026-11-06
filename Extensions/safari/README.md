# RamPart for Safari

Safari runs web extensions only from inside a signed `.appex` bundle embedded in a macOS app
(`RamPart.app/Contents/PlugIns/RamPartSafari.appex`). The JavaScript is the same as the Chromium
extension (`Extensions/chromium`); this folder holds the Safari manifest, the appex metadata and the
build script. The native side is `Sources/RampartSafariExtension` (`SafariWebExtensionHandler`),
which answers `browser.runtime.sendNativeMessage` with the same `NMRequest`/`NMResponse` contract as
`rampart-nmh`, using RampartWeb locally and rampartd over IPC when it runs.

## A. Build the appex without Xcode (default route)

```sh
Extensions/safari/build-appex.sh                       # → dist/RamPartSafari.appex, ad-hoc signed
Extensions/safari/build-appex.sh --app dist/RamPart.app # also copies it into Contents/PlugIns/
```

What the script does: compiles RampartShared + RampartWeb + the handler with `swiftc` (or
`swift build --product rampart-safari-ext` once Package.swift has that target), assembles
`Contents/MacOS/RamPartSafari`, `Contents/Info.plist` (`NSExtensionPointIdentifier =
com.apple.Safari.web-extension`, `NSExtensionPrincipalClass = SafariWebExtensionHandler`),
`Contents/Resources/` (manifest.json + shared JS/CSS/icons), then signs it with the sandbox
entitlements in `RamPartSafari.entitlements`.

**Package.swift target to add (lead):**
```swift
.executableTarget(name: "rampart-safari-ext", dependencies: ["RampartShared", "RampartWeb"],
                  path: "Sources/RampartSafariExtension",
                  linkerSettings: [.linkedFramework("SafariServices")]),
```
and `.executable(name: "rampart-safari-ext", targets: ["rampart-safari-ext"])` in `products`.

**scripts/build.sh integration (daemon/packaging agent):** after the app bundle is assembled and
before the final `codesign ... "$APP"` line, run
`Extensions/safari/build-appex.sh --sign "$SIGN_ID" --app "$APP"`. Nested code must be signed
before the outer app, which `build.sh` already re-signs last. Keep `com.apple.security.app-sandbox`
on the appex; Safari refuses unsandboxed extensions.

### Loading it in Safari (ad-hoc / self-signed builds)

Because the appex isn't signed with an Apple Developer ID, Safari treats it as unsigned:

1. Launch `RamPart.app` once (this registers the appex with Safari via LaunchServices).
2. Safari › Settings › Advanced › turn on **Show features for web developers**.
3. Develop › **Allow Unsigned Extensions** (asks for an administrator password).
   This resets every time Safari quits.
4. Safari › Settings › Extensions › tick **RamPart Web Protection**, and allow it on all websites.

The app's **"Set up Safari protection"** button (Sources/RampartApp/Features/SafariSetup) performs
steps 1–4 with the Accessibility API when the user presses it, pauses for the password sheet, and
can re-apply step 3 every time Safari launches (toggle). It needs Accessibility permission, which
the app requests once with a deep link.

With a paid Apple Developer ID the signing step changes to `--sign "Developer ID Application: …"`,
the extension loads without step 3, and the app can be notarized.

## B. Verifying without Xcode

- `plutil -lint` on the Info.plist, `codesign --verify --strict` on the appex (done by the script).
- `pluginkit -m -p com.apple.Safari.web-extension` lists registered extensions after launching the app once
  (read-only; not run during development).
- Unit coverage: the handler's request mapping is the same `WebVerdictService.handle` the selftest
  exercises through rampart-nmh.

## C. Optional fallback: "Safari JavaScript control" mode (lower security, off by default)

If the appex can't be loaded, RamPart can scan Safari pages by injecting its scanner through
Develop › **Allow JavaScript from Apple Events** and `do JavaScript` (needs the Automation permission
for Safari). **This setting lets any app that has Automation permission over Safari run script inside
every page, including banking sites, and macOS stealers abuse it.** RamPart therefore:

- keeps the mode off, behind an explicit "Advanced: lower security" confirmation, with one-click off;
- guards it while on (`RampartWeb.SafariScriptGuard`, UI in `SafariSetup`):
  1. **Sender control**: reads Automation grants (`kTCCServiceAppleEvents` → `com.apple.Safari`) from
     the user TCC database when Full Disk Access allows, and watches the unified log for TCC
     `AUTHREQ` entries targeting Safari. Any other app that holds or asks for that permission raises
     a detection, the mode switches itself off (Develop menu via the AX automation, or a clear
     instruction if that fails) and the user is offered `tccutil reset AppleEvents <bundle-id>`
     (runs only on click).
  2. **Process watch**: `osascript`/JXA invocations whose argv contains `do JavaScript`/`doJavaScript`
     aimed at Safari (from exec events and process sweeps), and `.scpt`/`.applescript` files that do,
     are flagged; unsigned or ad-hoc parents are treated as malicious.
  3. **In-page tamper detection**: the injected scanner (`jscontrol/scanner.js`) installs a
     MutationObserver plus API traps (new scripts/inline handlers after load, overrides of form
     submit/fetch/XMLHttpRequest/clipboard/input value getters compared with native-code snapshots,
     hidden iframes, keystroke listeners on password fields) and reports through the normal verdict
     channel. Weighed only on credential/payment pages or when a non-RamPart sender is present.
  4. The UI explains all of the above and that the risk is reduced, not zero.

Nothing in this folder runs automation during development; the planner and matchers are tested
against recorded AX fixtures in `SelfTest+Web.swift`.
