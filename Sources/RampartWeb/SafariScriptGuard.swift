import Foundation
import RampartShared

/// Guard for the optional "Safari JavaScript control" mode (Develop › Allow JavaScript from Apple Events).
/// While that setting is on, ANY app with Automation permission over Safari can run script in every page.
/// This type contains the pure logic: parsing TCC log lines and TCC.db rows, matching exec argv and
/// AppleScript sources, and turning findings into Detections. It never calls TCC, the log, or Safari
/// itself; the daemon/app feed it data (TelemetryKit exec events, `log stream` lines, TCC.db rows when
/// Full Disk Access permits).
public struct SafariScriptGuard: Sendable {
    public struct AppleEventsLogEvent: Hashable, Sendable {
        public enum Kind: String, Sendable { case request, granted, denied }
        public var kind: Kind
        public var client: String
        public var target: String
        public var pid: Int32?
    }
    public struct TCCRow: Hashable, Sendable {
        public var service: String
        public var client: String
        public var authValue: Int            // 0 denied, 1 unknown, 2 allowed, 3 limited
        public var indirectObject: String?
        public init(service: String, client: String, authValue: Int, indirectObject: String?) { self.service = service; self.client = client; self.authValue = authValue; self.indirectObject = indirectObject }
    }
    public struct Finding: Hashable, Sendable {
        public enum Source: String, Sendable { case tccLog, tccDatabase, processExec, scriptFile }
        public var source: Source
        public var bundleID: String?
        public var processPath: String?
        public var detail: String
        public var severity: Severity
        public var revokeCommand: String? { bundleID.map { "tccutil reset AppleEvents \($0)" } }
        public init(source: Source, bundleID: String?, processPath: String?, detail: String, severity: Severity) {
            self.source = source; self.bundleID = bundleID; self.processPath = processPath; self.detail = detail; self.severity = severity
        }
    }

    public static let safariBundleID = "com.apple.Safari"
    public let selfBundleIDs: Set<String>
    public init(selfBundleIDs: Set<String> = ["app.rampart.app", "app.rampart.daemon", "app.rampart.safari"]) { self.selfBundleIDs = selfBundleIDs }

    // MARK: Unified log (`log stream --style ndjson --predicate 'subsystem == "com.apple.TCC"'`)

    static let kv = try! NSRegularExpression(pattern: #"\b(service|client|client_pid|indirect_object_identifier|authValue|function)=([^,\s]+)"#)

    public static func parseLogLine(_ line: String) -> AppleEventsLogEvent? {
        guard line.contains("kTCCServiceAppleEvents") || line.contains("AUTHREQ_RESULT") else { return nil }
        let msg: String
        if let d = line.data(using: .utf8), let obj = try? JSONSerialization.jsonObject(with: d) as? [String: Any], let m = obj["eventMessage"] as? String { msg = m } else { msg = line }
        var fields: [String: String] = [:]
        for m in kv.matches(in: msg, range: NSRange(location: 0, length: (msg as NSString).length)) {
            fields[(msg as NSString).substring(with: m.range(at: 1))] = (msg as NSString).substring(with: m.range(at: 2))
        }
        guard let client = fields["client"], let target = fields["indirect_object_identifier"] else { return nil }
        if msg.contains("AUTHREQ_RESULT") {
            guard let v = fields["authValue"].flatMap({ Int($0) }) else { return nil }
            return AppleEventsLogEvent(kind: v == 2 || v == 3 ? .granted : .denied, client: client, target: target, pid: nil)
        }
        guard fields["service"] == "kTCCServiceAppleEvents" else { return nil }
        return AppleEventsLogEvent(kind: .request, client: client, target: target, pid: fields["client_pid"].flatMap { Int32($0) })
    }

    public func evaluate(event: AppleEventsLogEvent) -> Finding? {
        guard event.target == SafariScriptGuard.safariBundleID, !selfBundleIDs.contains(event.client), event.kind != .denied else { return nil }
        let what = event.kind == .granted ? "was granted" : "asked for"
        return Finding(source: .tccLog, bundleID: event.client, processPath: nil,
                       detail: "\(event.client) \(what) permission to control Safari while JavaScript from Apple Events was enabled.",
                       severity: event.kind == .granted ? .high : .medium)
    }

    // MARK: TCC.db rows (`SELECT service, client, auth_value, indirect_object_identifier FROM access`)

    /// Bundle IDs other than ours that currently hold Automation over Safari.
    public func foreignSafariAutomators(_ rows: [TCCRow]) -> [String] {
        rows.filter { $0.service == "kTCCServiceAppleEvents" && $0.indirectObject == SafariScriptGuard.safariBundleID && ($0.authValue == 2 || $0.authValue == 3) && !selfBundleIDs.contains($0.client) }
            .map(\.client).sorted()
    }

    // MARK: Process watch

    static let safariJS = try! NSRegularExpression(pattern: #"(?is)(application\s*\(?\s*["']Safari["']|tell\s+app(lication)?\s+["']Safari["']|com\.apple\.Safari|id\s+["']com\.apple\.Safari["']).{0,400}?(do\s+JavaScript|doJavaScript)|(do\s+JavaScript|doJavaScript).{0,400}?(application\s*\(?\s*["']Safari["']|tell\s+app(lication)?\s+["']Safari["']|com\.apple\.Safari)"#)

    public static func commandTargetsSafariJS(path: String, args: [String]) -> Bool {
        let name = (path as NSString).lastPathComponent
        guard ["osascript", "automator", "osacompile", "python", "python3", "swift", "node", "ruby", "perl"].contains(name) || args.contains(where: { $0.contains("JavaScript") }) else { return false }
        let joined = args.joined(separator: " ")
        return scriptSourceTargetsSafariJS(joined)
    }

    public static func scriptSourceTargetsSafariJS(_ source: String) -> Bool {
        safariJS.firstMatch(in: source, range: NSRange(location: 0, length: (source as NSString).length)) != nil
    }

    public func evaluate(exec p: ProcessInfoLite, parentSigningID: String?) -> Finding? {
        if let s = parentSigningID, selfBundleIDs.contains(s) { return nil }
        if let s = p.signingID, selfBundleIDs.contains(s) { return nil }
        guard SafariScriptGuard.commandTargetsSafariJS(path: p.path, args: p.args) else { return nil }
        let trusted = parentSigningID != nil && parentSigningID!.hasPrefix("com.apple.")
        return Finding(source: .processExec, bundleID: parentSigningID, processPath: p.path,
                       detail: "\(p.path) (pid \(p.pid)) sent “do JavaScript” to Safari" + (parentSigningID.map { " on behalf of \($0)" } ?? " from an unsigned or ad-hoc parent") + ".",
                       severity: trusted ? .medium : .high)
    }

    public func evaluate(scriptFile path: String, contents: String) -> Finding? {
        guard SafariScriptGuard.scriptSourceTargetsSafariJS(contents) else { return nil }
        return Finding(source: .scriptFile, bundleID: nil, processPath: path, detail: "Script \(path) contains “do JavaScript” targeting Safari.", severity: .medium)
    }

    public func detection(for f: Finding) -> Detection {
        Detection(path: f.processPath, name: "App scripting Safari pages", category: .suspicious, severity: f.severity, confidence: f.severity >= .high ? 80 : 55,
                  evidence: [Evidence(source: .behaviour, title: "Safari JavaScript control", detail: f.detail, score: f.severity >= .high ? 80 : 55)]
                      + (f.revokeCommand.map { [Evidence(source: .posture, title: "Revoke with", detail: $0, score: 0)] } ?? []))
    }
}

// MARK: - Accessibility tree model and matching (pure; the app's AX driver converts live AXUIElements into AXNode)

public final class AXNode: @unchecked Sendable {
    public let role: String
    public let title: String?
    public let value: String?
    public let children: [AXNode]
    public let ref: AnyObject?           // the live AXUIElement when built from a running app; nil in fixtures
    public init(role: String, title: String? = nil, value: String? = nil, children: [AXNode] = [], ref: AnyObject? = nil) {
        self.role = role; self.title = title; self.value = value; self.children = children; self.ref = ref
    }
    public func descendants() -> [AXNode] { [self] + children.flatMap { $0.descendants() } }
}

public struct AXTreeMatcher: Sendable {
    public init() {}
    static func norm(_ s: String?) -> String {
        (s ?? "").replacingOccurrences(of: "…", with: "").replacingOccurrences(of: "...", with: "")
            .folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil).trimmingCharacters(in: .whitespaces)
    }
    public func menuBarItem(in tree: AXNode, title: String) -> AXNode? {
        tree.descendants().first { $0.role == "AXMenuBarItem" && AXTreeMatcher.norm($0.title) == AXTreeMatcher.norm(title) }
    }
    public func menuItem(in tree: AXNode, menu: String, title: String) -> AXNode? {
        guard let bar = menuBarItem(in: tree, menu: menu) else { return nil }
        return bar.descendants().first { $0.role == "AXMenuItem" && AXTreeMatcher.norm($0.title) == AXTreeMatcher.norm(title) }
    }
    private func menuBarItem(in tree: AXNode, menu: String) -> AXNode? { menuBarItem(in: tree, title: menu) }
    public func checkbox(in tree: AXNode, titleContains: String) -> AXNode? {
        tree.descendants().first { $0.role == "AXCheckBox" && AXTreeMatcher.norm($0.title).contains(AXTreeMatcher.norm(titleContains)) }
    }
    public func toolbarButton(in tree: AXNode, title: String) -> AXNode? {
        tree.descendants().first { n in n.role == "AXToolbar" }?.descendants().first { $0.role == "AXButton" && AXTreeMatcher.norm($0.title) == AXTreeMatcher.norm(title) }
            ?? tree.descendants().first { $0.role == "AXButton" && AXTreeMatcher.norm($0.title) == AXTreeMatcher.norm(title) }
    }
    public func extensionCheckbox(in tree: AXNode, nameContains: String) -> AXNode? {
        guard let win = tree.children.first(where: { $0.role == "AXWindow" && AXTreeMatcher.norm($0.title) == "extensions" }) ?? tree.descendants().first(where: { $0.role == "AXWindow" && AXTreeMatcher.norm($0.title) == "extensions" }) else { return nil }
        return checkbox(in: win, titleContains: nameContains)
    }
    /// The admin-password sheet macOS shows for "Allow Unsigned Extensions".
    public func passwordSheet(in tree: AXNode) -> AXNode? {
        tree.descendants().first { n in n.role == "AXSheet" && n.descendants().contains { $0.role == "AXSecureTextField" } }
    }
}

/// Decides which AX presses are needed to reach the desired Safari state. Pure: input is a tree snapshot.
public enum SafariSetupPlanner {
    public struct Step: Hashable, Sendable {
        public enum Kind: String, Sendable { case pressCheckbox, pressMenuItem, waitForPasswordSheet, pressExtensionCheckbox, openSettingsPane }
        public var kind: Kind
        public var target: String
        public var reason: String
    }
    public struct Plan: Sendable { public var steps: [Step]; public var notes: [String] }

    public static func plan(tree: AXNode, extensionName: String, wantJSFromAppleEvents: Bool) -> Plan {
        let m = AXTreeMatcher()
        var steps: [Step] = [], notes: [String] = []
        let develop = m.menuBarItem(in: tree, title: "Develop")
        let devFeatures = m.checkbox(in: tree, titleContains: "features for web developers")
        if develop == nil || devFeatures?.value == "0" {
            steps.append(Step(kind: .pressCheckbox, target: "Show features for web developers", reason: "The Develop menu is hidden until this is on (Settings › Advanced)."))
        }
        let unsigned = m.menuItem(in: tree, menu: "Develop", title: "Allow Unsigned Extensions")
        if unsigned == nil || unsigned?.value != "1" {
            steps.append(Step(kind: .pressMenuItem, target: "Allow Unsigned Extensions", reason: "Lets Safari load the RamPart extension without an Apple-signed app."))
            steps.append(Step(kind: .waitForPasswordSheet, target: "Password", reason: "macOS asks for your password here. RamPart waits; you type it."))
        }
        let ext = m.extensionCheckbox(in: tree, nameContains: extensionName)
        if ext == nil || ext?.value != "1" {
            steps.append(Step(kind: .pressExtensionCheckbox, target: extensionName, reason: "Turns the extension on in Settings › Extensions."))
            if ext == nil { notes.append("The extension row wasn't visible yet; Safari lists it after the app has been launched once.") }
        }
        let js = m.menuItem(in: tree, menu: "Develop", title: "Allow JavaScript from Apple Events")
        let jsOn = js?.value == "1"
        if jsOn != wantJSFromAppleEvents, js != nil || wantJSFromAppleEvents {
            steps.append(Step(kind: .pressMenuItem, target: "Allow JavaScript from Apple Events", reason: wantJSFromAppleEvents ? "Enables the lower-security JavaScript control mode you chose." : "Turns off the lower-security setting that lets any automated app run script in Safari pages."))
        }
        return Plan(steps: steps, notes: notes)
    }
}
