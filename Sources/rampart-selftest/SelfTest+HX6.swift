import Foundation

// hx6: RamPart Secure Browser + Safari integration hardening.
// RampartBrowser, RampartApp and the Safari appex are executable targets this binary can't import, so
// (1) the browser's pure hx6 regressions run through its headless `--selftest` mode (exits before AppKit:
// no window, no WebKit, no network) when the binary sits next to this one, and (2) the shipped JS and
// manifest are checked as text for the protections the Swift side relies on.
extension SelfTest {
    static func hx6Checks() {
        let root = hx6RepoRoot()
        func read(_ rel: String) -> String { (try? String(contentsOfFile: root + "/" + rel, encoding: .utf8)) ?? "" }

        // JS-control banner: draws only on the judged page; placeholders filled in one pass.
        let banner = read("Extensions/safari/jscontrol/banner.js")
        check(banner.contains("__EXPECTED_URL__") && banner.contains("strip(location.href) !== strip(expected)"), "hx6 banner checks it is still on the judged page")
        check(banner.components(separatedBy: "__HEADLINE__").count == 2 && banner.components(separatedBy: "__REASONS__").count == 2, "hx6 banner placeholders appear once (not in comments)")
        // JS-control scanner: no well-known global a page can pre-plant.
        let scanner = read("Extensions/safari/jscontrol/scanner.js")
        check(scanner.contains("__RAMPART_NONCE__") && !scanner.contains("W.__rampartTamper ="), "hx6 scanner state keyed by a per-session nonce")
        check(scanner.contains("enumerable: false, writable: false, configurable: false"), "hx6 scanner state locked")
        // Swift side of JS control: Safari's URL is authoritative, timeout set, one-pass fill.
        let js = read("Sources/RampartApp/Features/SafariSetup/SafariJSControlScript.swift")
        check(js.contains("with timeout of") && js.contains("set u to URL of t"), "hx6 AppleScript has a timeout and reads Safari's own URL")
        let model = read("Sources/RampartApp/Features/SafariSetup/SafariSetupModel.swift")
        check(model.contains("let url = reply.safariURL") && model.contains("SafariJSControlScript.fillBanner"), "hx6 verdict uses Safari's URL; banner filled in one pass")
        check(!model.contains("replacingOccurrences(of: \"__HEADLINE__\""), "hx6 old chained placeholder replace gone")
        check(model.contains("SafariAXDriver.exactExtensionCheckbox"), "hx6 setup enables only the exact RamPart row")
        let ax = read("Sources/RampartApp/Features/SafariSetup/SafariAXDriver.swift")
        check(ax.contains("kAXMenuItemMarkCharAttribute"), "hx6 menu item state read from the mark character")
        // Extension handler validates before decoding.
        let handler = read("Sources/RampartSafariExtension/SafariWebExtensionHandler.swift")
        check(handler.contains("SafariMessageValidator.validate(payload)") && handler.contains("PublicSuffix.split(host)"), "hx6 Safari handler validates messages and refuses public-suffix allowHost")

        // Browser pure-logic suite (includes BrowserSelfTests.hx6()).
        let exe = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().appendingPathComponent("RampartBrowser")
        guard FileManager.default.isExecutableFile(atPath: exe.path) else {
            print("  hx6: RampartBrowser binary not built next to rampart-selftest; build --product RampartBrowser to run its suite")
            return
        }
        let p = Process(); p.executableURL = exe; p.arguments = ["--selftest"]
        var env = ProcessInfo.processInfo.environment; env["RAMPART_NO_PRIVILEGED_TOOLS"] = "1"; p.environment = env
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe
        do { try p.run() } catch { check(false, "hx6 browser selftest launches"); return }
        let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        p.waitUntilExit()
        for line in out.split(separator: "\n") where line.hasPrefix("FAIL") { print("  " + line) }
        check(p.terminationStatus == 0 && out.contains("0 failed"), "hx6 RampartBrowser --selftest passes (\(out.split(separator: "\n").last ?? ""))")
    }

    private static func hx6RepoRoot() -> String {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<4 { dir.deleteLastPathComponent(); if FileManager.default.fileExists(atPath: dir.appendingPathComponent("Package.swift").path) { return dir.path } }
        return FileManager.default.currentDirectoryPath
    }
}
