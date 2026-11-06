import Foundation
import AppKit
import ApplicationServices
import RampartWeb

// Accessibility driver for the Safari setup automation. Only ever invoked from the user's button
// press in SafariSetupView; nothing here runs at launch or in the background except the
// NSWorkspace launch observer the user opted into. Pure matching/planning lives in RampartWeb
// (AXTreeMatcher / SafariSetupPlanner) so it can be tested against fixtures without touching AX.

enum SafariAXError: LocalizedError {
    case notTrusted, safariNotRunning, elementMissing(String), pressFailed(String), timeout(String), cancelled
    var errorDescription: String? {
        switch self {
        case .notTrusted: return "RamPart needs Accessibility permission to click Safari's menus for you."
        case .safariNotRunning: return "Safari didn't start."
        case .elementMissing(let s): return "Couldn't find “\(s)” in Safari. Safari's menus may be in another language or version; finish the step by hand."
        case .pressFailed(let s): return "Couldn't press “\(s)”."
        case .timeout(let s): return "Timed out waiting for \(s)."
        case .cancelled: return "Cancelled."
        }
    }
}

@MainActor
final class SafariAXDriver {
    static let safariBundleID = "com.apple.Safari"

    /// Read-only check; never shows the system prompt.
    static var isTrusted: Bool { AXIsProcessTrusted() }

    /// Deep-links to Privacy & Security › Accessibility. User-initiated only.
    static func openAccessibilitySettings() {
        if let u = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility") { NSWorkspace.shared.open(u) }
    }

    static func runningSafari() -> NSRunningApplication? { NSRunningApplication.runningApplications(withBundleIdentifier: safariBundleID).first }

    /// Launches Safari (user-initiated) and returns once it is running.
    static func launchSafari() async throws -> NSRunningApplication {
        if let s = runningSafari() { s.activate(); return s }
        guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: safariBundleID) else { throw SafariAXError.safariNotRunning }
        let cfg = NSWorkspace.OpenConfiguration(); cfg.activates = true
        let app = try await NSWorkspace.shared.openApplication(at: url, configuration: cfg)
        for _ in 0..<40 { if app.isFinishedLaunching { return app }; try await Task.sleep(nanoseconds: 250_000_000) }
        return app
    }

    // MARK: Snapshot

    private static func attr(_ el: AXUIElement, _ name: String) -> AnyObject? {
        var v: AnyObject?
        return AXUIElementCopyAttributeValue(el, name as CFString, &v) == .success ? v : nil
    }

    /// Converts the live AX tree of an app into the fixture-compatible AXNode model.
    /// Depth and node limits keep this cheap (Safari's web content is skipped: AXWebArea subtrees are not descended).
    static func snapshot(pid: pid_t, maxDepth: Int = 12, maxNodes: Int = 4000) -> AXNode {
        let app = AXUIElementCreateApplication(pid)
        var count = 0
        func build(_ el: AXUIElement, depth: Int) -> AXNode {
            count += 1
            let role = (attr(el, kAXRoleAttribute) as? String) ?? "?"
            let title = (attr(el, kAXTitleAttribute) as? String) ?? (attr(el, kAXDescriptionAttribute) as? String)
            var value: String? = nil
            if let v = attr(el, kAXValueAttribute) {
                if let n = v as? NSNumber { value = n.stringValue } else if let s = v as? String { value = s }
            }
            var children: [AXNode] = []
            if depth < maxDepth, count < maxNodes, role != "AXWebArea", role != "AXScrollArea" || title != nil {
                if let kids = attr(el, kAXChildrenAttribute) as? [AXUIElement] {
                    for k in kids.prefix(200) where count < maxNodes { children.append(build(k, depth: depth + 1)) }
                }
            }
            return AXNode(role: role, title: title, value: value, children: children, ref: el)
        }
        var root = build(app, depth: 0)
        // Menu bar is a separate attribute, not always in children.
        if !root.descendants().contains(where: { $0.role == "AXMenuBar" }), let mb = attr(app, kAXMenuBarAttribute) {
            let mbNode = build(mb as! AXUIElement, depth: 1)
            root = AXNode(role: root.role, title: root.title, value: root.value, children: root.children + [mbNode], ref: root.ref)
        }
        return root
    }

    static func press(_ node: AXNode, name: String) throws {
        guard let el = node.ref else { throw SafariAXError.elementMissing(name) }
        let r = AXUIElementPerformAction(el as! AXUIElement, kAXPressAction as CFString)
        guard r == .success else { throw SafariAXError.pressFailed(name) }
    }

    /// Polls the tree until `predicate` finds a node, or times out.
    static func wait(pid: pid_t, seconds: Double, what: String, _ predicate: (AXNode) -> AXNode?) async throws -> AXNode {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            try Task.checkCancellation()
            if let n = predicate(snapshot(pid: pid)) { return n }
            try await Task.sleep(nanoseconds: 400_000_000)
        }
        throw SafariAXError.timeout(what)
    }

    /// Waits until a node matching `predicate` is NOT present (e.g. the password sheet went away).
    static func waitGone(pid: pid_t, seconds: Double, what: String, _ predicate: (AXNode) -> AXNode?) async throws {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            try Task.checkCancellation()
            if predicate(snapshot(pid: pid)) == nil { return }
            try await Task.sleep(nanoseconds: 500_000_000)
        }
        throw SafariAXError.timeout(what)
    }
}
