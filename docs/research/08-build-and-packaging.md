# 08 — Build and Packaging Without Xcode

Tested 2026-11-05 on macOS 27.0.1 (26A434), arm64, with Command Line Tools only (`/Library/Developer/CommandLineTools`) and Swift 6.4 (swiftlang-6.4.0.34.1). The prototype is in the scratchpad (`pkgtest/`).

## Verdict

| Capability | Status without Xcode | Notes |
|---|---|---|
| `swift build` of a SwiftUI + AppKit `@main App` | WORKS (verified) | Needs the `@State` workaround below |
| `-Xswiftc -parse-as-library` | NOT NEEDED (verified) | SwiftPM passes `-parse-as-library` itself when the `@main` file is not named `main.swift`. Do not call the file `main.swift`. |
| `@State` macro | BROKEN (verified) | The CLT ship no `SwiftUIMacros` plugin. Workaround: `typealias StateVar = SwiftUI.State` |
| `@Observable`, `@StateObject`/`@Published`, `@Bindable` | WORKS (verified) | The `ObservationMacros` plugin ships with the CLT |
| `#Preview`, `@Entry`, `@Previewable`, `@Animatable` | BROKEN (inferred) | Same missing macro plugins (`SwiftUIMacros`, `PreviewsMacros`). Avoid them. |
| Hand-assembled .app bundle, window, Dock icon, menu bar | WORKS (verified by screenshot) | Window, Dock icon, app menu, and NSStatusItem all appear |
| Icon via `sips` + `iconutil` | WORKS (verified) | |
| Ad-hoc `codesign` with entitlements and hardened runtime | WORKS (verified) | `codesign --verify --strict` passes. `spctl` rejects it, as expected for ad-hoc. |
| DMG | WORKS (verified) | `hdiutil create` is DEPRECATED on macOS 27 (it still works but warns). Use `diskutil image create from`. |
| PKG (`pkgbuild` + `productbuild`) | WORKS (verified) | Prints harmless `write: Permission denied` lines in our sandboxed shell (see Pitfalls) |
| UserNotifications from a non-Xcode bundle | API WORKS, delivery needs user consent | `Bundle.main.bundleIdentifier` resolves. `requestAuthorization` returned `UNErrorDomain Code=1 "Notifications are not allowed"`. See Pitfalls. |
| SMAppService (login item, agent, daemon) | API links and runs | `SMAppService.mainApp.status` = 3 (`.notFound`) for the bundle in the scratchpad. I did not call `register()` in this session (see below). |
| Privileged daemon via sudo, osascript, or SMAppService.daemon | NOT EXECUTED | This needs admin rights and changes the system. I documented the recipes but did not run them. |

## Package.swift skeleton (verified)

```swift
// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "Bastion",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "BastionApp", targets: ["BastionApp"]),
        .executable(name: "BastionHelper", targets: ["BastionHelper"]),
    ],
    targets: [
        .executableTarget(
            name: "BastionApp",
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("SwiftUI"),
                .linkedFramework("ServiceManagement"),
                .linkedFramework("UserNotifications"),
            ]
        ),
        .executableTarget(name: "BastionHelper"),
    ]
)
```

Layout:
```
Package.swift
Sources/BastionApp/BastionApp.swift   # @main App. Must NOT be named main.swift
Sources/BastionHelper/main.swift      # helper/daemon. Top-level code is fine here
Packaging/Info.plist  Packaging/Bastion.entitlements
Packaging/com.bastion.helper.plist  Packaging/com.bastion.helper.agent.plist
Packaging/make-icon-png.swift         # placeholder icon renderer
build.sh
```

## App entry point (verified to compile, launch, and show a window, Dock icon, and status item)

```swift
import SwiftUI
import AppKit
import ServiceManagement
import UserNotifications

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    var statusItem: NSStatusItem?

    func applicationDidFinishLaunching(_ notification: Notification) {
        setvbuf(stdout, nil, _IOLBF, 0)
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.image = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "Bastion")
        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "Open Bastion", action: #selector(openMain), keyEquivalent: "o"))
        menu.addItem(NSMenuItem(title: "Test Notification", action: #selector(testNotify), keyEquivalent: "n"))
        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
        for i in menu.items where i.action != #selector(NSApplication.terminate(_:)) { i.target = self }
        item.menu = menu
        statusItem = item

        let center = UNUserNotificationCenter.current()
        center.delegate = self
        center.requestAuthorization(options: [.alert, .sound, .badge]) { granted, err in
            print("notif auth granted=\(granted) err=\(String(describing: err))")
        }
        print("bundleID=\(Bundle.main.bundleIdentifier ?? "nil")")
        print("SMAppService.mainApp.status=\(SMAppService.mainApp.status.rawValue)")
        if CommandLine.arguments.contains("--register-login") {
            do { try SMAppService.mainApp.register(); print("login item registered") }
            catch { print("login register error: \(error)") }
            print("status after=\(SMAppService.mainApp.status.rawValue)")
        }
        if CommandLine.arguments.contains("--unregister-login") {
            do { try SMAppService.mainApp.unregister(); print("login item unregistered") }
            catch { print("unregister error: \(error)") }
        }
        if CommandLine.arguments.contains("--agent-status") {
            let a = SMAppService.agent(plistName: "com.bastion.helper.agent.plist")
            print("agent status=\(a.status.rawValue)")
            do { try a.register(); print("agent registered status=\(a.status.rawValue)") } catch { print("agent register error: \(error)") }
            try? a.unregister()
            let d = SMAppService.daemon(plistName: "com.bastion.helper.plist")
            print("daemon status=\(d.status.rawValue)")
            do { try d.register(); print("daemon registered status=\(d.status.rawValue)") } catch { print("daemon register error: \(error)") }
        }
        if CommandLine.arguments.contains("--notify") {
            DispatchQueue.main.asyncAfter(deadline: .now() + 1) { self.testNotify() }
        }
    }

    @objc func openMain() {
        NSApp.activate(ignoringOtherApps: true)
        NSApp.windows.first { $0.canBecomeMain }?.makeKeyAndOrderFront(nil)
    }

    @objc func testNotify() {
        let c = UNMutableNotificationContent()
        c.title = "Bastion"
        c.body = "Threat quarantined: test.eicar"
        let req = UNNotificationRequest(identifier: UUID().uuidString, content: c, trigger: nil)
        UNUserNotificationCenter.current().add(req) { err in print("notify add err=\(String(describing: err))") }
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .sound]
    }
}

@main
struct BastionApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    var body: some Scene {
        WindowGroup("Bastion") {
            ContentView().frame(minWidth: 420, minHeight: 280)
        }
        Settings { Text("Settings").padding() }
    }
}

struct ContentView: View {
    @StateVar private var count = 0
    @StateObject private var model = ScanModel()
    @Bindable private var obs = ObsModel.shared
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "shield.lefthalf.filled").font(.system(size: 48))
            Text("Bastion is protecting this Mac").font(.title2)
            Button("Scan (\(count))") { count += 1 }
            Button("Model (\(model.n))") { model.n += 1 }
            Toggle("Realtime", isOn: $obs.realtime)
        }.padding()
    }
}

/// CLT ships no SwiftUIMacros plugin: `@State` resolves to the macro and fails. Use the wrapper struct via typealias.
typealias StateVar = SwiftUI.State

final class ScanModel: ObservableObject { @Published var n = 0 }

import Observation
@Observable final class ObsModel { @MainActor static let shared = ObsModel(); var realtime = true }
```

Notes:
- `NSApp.setActivationPolicy(.regular)` together with `LSUIElement=false` gives a Dock icon and a menu bar. For a menu-bar-only agent, use `LSUIElement=true` or `.accessory`, and switch to `.regular` at runtime when the main window opens.
- Mark `AppDelegate` `@MainActor` (Swift 6 strict concurrency). Delegate callbacks that are async and receive non-Sendable UN types must be `nonisolated`. Otherwise you get the error `non-Sendable parameter type 'UNNotification' cannot be sent...`.

## Info.plist template (verified with `plutil -lint`)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key><string>en</string>
    <key>CFBundleExecutable</key><string>Bastion</string>
    <key>CFBundleIdentifier</key><string>com.bastion.app</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>CFBundleName</key><string>Bastion</string>
    <key>CFBundleDisplayName</key><string>Bastion</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>__VERSION__</string>
    <key>CFBundleVersion</key><string>__BUILD__</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
    <key>LSUIElement</key><false/>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSPrincipalClass</key><string>NSApplication</string>
    <key>NSHumanReadableCopyright</key><string>Copyright 2026 Bastion</string>
    <key>NSAppleEventsUsageDescription</key><string>Bastion uses Apple Events to request administrator privileges for installing its protection helper.</string>
    <key>NSUserNotificationsUsageDescription</key><string>Bastion alerts you when threats are detected.</string>
</dict>
</plist>
```

## Entitlements (ad-hoc signed and verified)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.automation.apple-events</key><true/>
</dict>
</plist>
```
Add `com.apple.developer.endpoint-security.client` only after Apple grants it. It requires a Developer ID provisioning profile, and an ad-hoc-signed binary that claims it is killed at launch. The app is not sandboxed, so we add no `com.apple.security.app-sandbox`. An AV needs broad file access through Full Disk Access instead.

## LaunchDaemon plist (bundled, for SMAppService.daemon)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.bastion.helper</string>
    <key>BundleProgram</key><string>Contents/MacOS/BastionHelper</string>
    <key>AssociatedBundleIdentifiers</key><array><string>com.bastion.app</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><false/>
    <key>StandardOutPath</key><string>/tmp/bastion-helper.log</string>
    <key>StandardErrorPath</key><string>/tmp/bastion-helper.log</string>
</dict>
</plist>
```
The plist goes in `Bastion.app/Contents/Library/LaunchDaemons/`. Agent plists go in `Contents/Library/LaunchAgents/`. `BundleProgram` is relative to the bundle.

## build.sh (verified end to end: exit 0, produces .app, .dmg, .pkg)

```bash
#!/bin/bash
# Bastion: build + bundle + ad-hoc sign + DMG + PKG, using only Command Line Tools.
set -euo pipefail
cd "$(dirname "$0")"

APP_NAME="Bastion"
BUNDLE_ID="com.bastion.app"
VERSION="${VERSION:-0.1.0}"
BUILD="${BUILD:-$(date +%Y%m%d%H%M)}"
CONFIG="${CONFIG:-release}"
SIGN_ID="${SIGN_ID:--}"            # "-" = ad-hoc. Set to "Developer ID Application: ..." later.
DIST="dist"
APP="$DIST/$APP_NAME.app"

echo "==> swift build ($CONFIG)"
swift build -c "$CONFIG" --product BastionApp
swift build -c "$CONFIG" --product BastionHelper
BIN="$(swift build -c "$CONFIG" --show-bin-path)"

echo "==> assemble $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APP/Contents/Library/LaunchDaemons" "$APP/Contents/Library/LaunchAgents"
cp "$BIN/BastionApp"    "$APP/Contents/MacOS/$APP_NAME"
cp "$BIN/BastionHelper" "$APP/Contents/MacOS/BastionHelper"
sed -e "s/__VERSION__/$VERSION/" -e "s/__BUILD__/$BUILD/" Packaging/Info.plist > "$APP/Contents/Info.plist"
printf 'APPL????' > "$APP/Contents/PkgInfo"
# SMAppService.daemon/agent(plistName:) look in these exact dirs inside the bundle:
cp Packaging/com.bastion.helper.plist       "$APP/Contents/Library/LaunchDaemons/"
cp Packaging/com.bastion.helper.agent.plist "$APP/Contents/Library/LaunchAgents/"
# SwiftPM resource bundles (only exist if targets declare resources:)
for b in "$BIN"/*.bundle; do [ -e "$b" ] && cp -R "$b" "$APP/Contents/Resources/"; done
plutil -lint "$APP/Contents/Info.plist"

echo "==> icon"
ICON_SRC="${ICON_SRC:-Packaging/AppIcon-1024.png}"
[ -f "$ICON_SRC" ] || swift Packaging/make-icon-png.swift "$ICON_SRC"
ICONSET="$DIST/AppIcon.iconset"; rm -rf "$ICONSET"; mkdir -p "$ICONSET"
for s in 16 32 128 256 512; do
  sips -z $s $s           "$ICON_SRC" --out "$ICONSET/icon_${s}x${s}.png"    >/dev/null
  sips -z $((s*2)) $((s*2)) "$ICON_SRC" --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
rm -rf "$ICONSET"

echo "==> codesign ($SIGN_ID)"
# Sign inside-out (nested executables first). --deep is deprecated for signing; explicit is safer.
codesign --force --options runtime --timestamp=none -s "$SIGN_ID" \
  --identifier com.bastion.helper "$APP/Contents/MacOS/BastionHelper"
codesign --force --options runtime --timestamp=none -s "$SIGN_ID" \
  --entitlements Packaging/Bastion.entitlements "$APP"
codesign --verify --strict --verbose=2 "$APP"
codesign -d --entitlements - "$APP" 2>/dev/null | tail -n +1 >/dev/null

echo "==> DMG"
STAGE="$DIST/dmg-stage"; rm -rf "$STAGE" "$DIST/$APP_NAME.dmg"; mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
# macOS 27 deprecates `hdiutil create` (still works, prints a warning); prefer diskutil image.
if diskutil image create from --help >/dev/null 2>&1; then
  diskutil image create from --format UDZO --volumeName "$APP_NAME" "$STAGE" "$DIST/$APP_NAME.dmg" >/dev/null 2>&1
else
  hdiutil create -volname "$APP_NAME" -srcfolder "$STAGE" -ov -format UDZO "$DIST/$APP_NAME.dmg" >/dev/null 2>&1
fi
rm -rf "$STAGE"
codesign --force -s "$SIGN_ID" "$DIST/$APP_NAME.dmg"
hdiutil verify "$DIST/$APP_NAME.dmg" >/dev/null 2>&1 && echo "dmg ok"

echo "==> PKG"
PKGROOT="$DIST/pkgroot"; rm -rf "$PKGROOT"; mkdir -p "$PKGROOT/Applications"
cp -R "$APP" "$PKGROOT/Applications/"
pkgbuild --analyze --root "$PKGROOT" "$DIST/components.plist" >/dev/null
# Don't let Installer "relocate" the app to wherever a same-ID copy lives (e.g. .build or dist/)
/usr/libexec/PlistBuddy -c "Add :0:BundleIsRelocatable bool false" "$DIST/components.plist"
pkgbuild --root "$PKGROOT" --component-plist "$DIST/components.plist" \
  --identifier "$BUNDLE_ID.pkg" --version "$VERSION" --install-location / \
  ${PKG_SCRIPTS:+--scripts "$PKG_SCRIPTS"} "$DIST/$APP_NAME-component.pkg"
productbuild --package "$DIST/$APP_NAME-component.pkg" "$DIST/$APP_NAME.pkg"
rm -rf "$PKGROOT" "$DIST/components.plist" "$DIST/$APP_NAME-component.pkg"
pkgutil --payload-files "$DIST/$APP_NAME.pkg" > "$DIST/pkg-files.txt" && wc -l < "$DIST/pkg-files.txt"

echo "==> done: $APP  $DIST/$APP_NAME.dmg  $DIST/$APP_NAME.pkg"
```
Icon placeholder renderer (`Packaging/make-icon-png.swift`, runs with `swift file.swift`):
```swift
// Renders a placeholder 1024x1024 PNG icon (replace with real artwork later).
import AppKit
let size = 1024
let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
let r = NSRect(x: 100, y: 100, width: 824, height: 824)
NSColor(calibratedRed: 0.1, green: 0.3, blue: 0.7, alpha: 1).setFill()
NSBezierPath(roundedRect: r, xRadius: 185, yRadius: 185).fill()
if let sym = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: nil)?
    .withSymbolConfiguration(.init(pointSize: 520, weight: .bold).applying(.init(paletteColors: [.white]))) {
    let s = sym.size
    sym.draw(in: NSRect(x: (1024 - s.width)/2, y: (1024 - s.height)/2, width: s.width, height: s.height))
}
NSGraphicsContext.restoreGraphicsState()
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
```

Run: `./build.sh`, then `open dist/Bastion.app`. A rebuild after the first one takes about 2 s. The first clean release build took about 58 s.

## Launch at login

- **SMAppService.mainApp.register()** (macOS 13+) is preferred. It needs a signed bundle with a stable bundle ID, ideally installed in `/Applications`. Check `.status`: 0 notRegistered, 1 enabled, 2 requiresApproval, 3 notFound. Our scratchpad copy reported **3 (notFound)** before registration. Run the registration test from `/Applications/Bastion.app` once the .pkg is installed. The user can see and revoke the item in System Settings > General > Login Items.
- **SMAppService.agent(plistName:)** uses `Contents/Library/LaunchAgents/<name>.plist`.
- Fallback: a classic LaunchAgent plist at `~/Library/LaunchAgents/com.bastion.app.plist` with `ProgramArguments=[/Applications/Bastion.app/Contents/MacOS/Bastion]` and `RunAtLoad=true`, loaded with `launchctl bootstrap gui/$(id -u) <plist>`. Since macOS 13 the user is notified about it as a "background item".

## Privileged helper (recipes, NOT executed in this session)

1. **SMAppService.daemon(plistName: "com.bastion.helper.plist").register()** is the modern path. It returns `.requiresApproval` and the user approves it in Login Items. It needs a signed bundle. Whether ad-hoc signatures are accepted for daemons on macOS 27 is UNVERIFIED. Historically Apple has required a real Team ID for the `AssociatedBundleIdentifiers` linkage, so expect to need a Developer ID.
2. **osascript with admin prompt** (works with ad-hoc signing, but is a legacy UX):
   ```bash
   osascript -e 'do shell script "cp /Applications/Bastion.app/Contents/Library/LaunchDaemons/com.bastion.helper.plist /Library/LaunchDaemons/ && chown root:wheel /Library/LaunchDaemons/com.bastion.helper.plist && launchctl bootstrap system /Library/LaunchDaemons/com.bastion.helper.plist" with administrator privileges'
   ```
   For a /Library/LaunchDaemons copy, use `ProgramArguments` with an absolute path. `BundleProgram` is only understood by SMAppService. Calling this from inside the app via `NSAppleScript` requires `NSAppleEventsUsageDescription` and the apple-events entitlement, both of which are included above.
3. **.pkg postinstall script**: pass `PKG_SCRIPTS=Packaging/scripts ./build.sh`, with a `postinstall` that runs `launchctl bootstrap system ...`. The Installer already runs as root, which makes this the cleanest path for distribution.
4. `AuthorizationExecuteWithPrivileges` has been deprecated since 10.7. Do not use it. `SMJobBless` is deprecated in favour of SMAppService.

## Pitfalls actually hit

1. **`@State` fails to compile under CLT**: `external macro implementation type 'SwiftUIMacros.StateMacro' could not be found ... plugin for module 'SwiftUIMacros' not found`. This follows the error `left side of mutating operator isn't mutable`. In the macOS 27 SDK, `@State` resolves to a macro, and its plugin only ships with Xcode. Fix: `typealias StateVar = SwiftUI.State` and use `@StateVar`. Alternatively, use `@Observable` classes (Observation macros do ship) or `ObservableObject`/`@StateObject`. Ban `#Preview`/`@Entry` in the codebase.
2. **Swift 6 actor isolation**: an `NSApplicationDelegate` that is not `@MainActor` produces warnings for every `NSApp` access. A `@MainActor` delegate with an async `UNUserNotificationCenterDelegate` method is a hard error until you mark the method `nonisolated`.
3. **`-parse-as-library` is not needed.** SwiftPM adds it already (seen in the frontend command line). The real trap is naming the file `main.swift` while also using `@main`.
4. **`ld: warning: search path '/Library/Developer/CommandLineTools/Developer/Library/Frameworks' not found`** appears on every link. It is harmless and can be ignored.
5. **`hdiutil create` is deprecated on macOS 27** ("Please use 'diskutil image create from/blank'"). `diskutil image create from --format UDZO --volumeName X <folder> <out.dmg>` works and creates an APFS image. `hdiutil verify` and `imageinfo` also warn but work. Its progress output goes to stderr, so silence it.
6. **`pkgbuild --analyze` no longer emits a `BundleIsRelocatable` key**, so `PlistBuddy Set` fails with `Does Not Exist`. Use `Add :0:BundleIsRelocatable bool false`. Without it, Installer may "relocate" the install onto a stray copy of the app with the same bundle ID, such as `dist/` or `.build/`.
7. **`pkgbuild` printed `write: Permission denied` ×4** in our sandboxed agent shell. The package was still produced and `pkgutil --payload-files` listed 18 entries. This is probably caused by the sandbox, so re-check it in a normal Terminal.
8. **`pkgutil ... | head` under `set -o pipefail`** triggered SIGPIPE noise. Write the output to a file instead.
9. **stdout is block-buffered** when an app is launched via `open --stdout file`, so the log looked empty. Call `setvbuf(stdout, nil, _IOLBF, 0)`, or better, use `os.Logger` and `log show --predicate 'subsystem == "com.bastion.app"'`.
10. **Notifications**: `requestAuthorization` returned `UNErrorDomain Code=1 "Notifications are not allowed for this application"` for the ad-hoc-signed bundle run from the scratchpad path. Either the first-run permission prompt was not answered or was dismissed, or the system will not register the unregistered or temporary location. Next step: install to `/Applications` (through the .pkg), launch once with `open`, and check System Settings > Notifications > Bastion. Also run `/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Bastion.app`. Fallback for alerts: `osascript -e 'display notification ...'`, which posts under Script Editor's identity, or an in-app NSAlert or NSPanel.
11. **Gatekeeper**: `spctl -a -vv` reports `rejected` for ad-hoc signing. Local builds have no quarantine attribute and run fine. A downloaded DMG or PKG will be blocked until it is Developer ID signed and notarized (`xcrun notarytool` is included in CLT, but it needs an Apple Developer account). Users can work around this with right-click > Open, or by allowing it in System Settings > Privacy & Security.
12. **`codesign --deep` is deprecated for signing.** Sign nested executables first (the helper), then the outer bundle, as `build.sh` does. Using `--options runtime` (hardened runtime) is fine ad-hoc and is required later for notarization.
