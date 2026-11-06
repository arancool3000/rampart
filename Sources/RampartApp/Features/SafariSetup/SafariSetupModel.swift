import Foundation
import AppKit
import SwiftUI
import Observation
import SQLite3
import RampartShared
import RampartWeb

// One-button Safari setup, the "re-enable on Safari launch" watcher, and the optional lower-security
// "Safari JavaScript control" mode with its guard. Everything that touches Safari, Accessibility, Apple
// Events or TCC runs only after the user presses a button in SafariSetupView. Pure decision logic
// (AXTreeMatcher, SafariSetupPlanner, SafariScriptGuard) lives in RampartWeb and is fixture-tested.

@MainActor
@Observable
final class SafariSetupModel {
    enum Phase: Equatable {
        case idle, needsAccessibility, launching, running(step: String, index: Int, total: Int), waitingForPassword, done(summary: String), failed(message: String), cancelled
        var isActive: Bool { switch self { case .launching, .running, .waitingForPassword: return true; default: return false } }
    }
    var phase: Phase = .idle
    var countdown: Int = 0
    var planNotes: [String] = []
    @ObservationIgnored private var task: Task<Void, Never>? = nil
    @ObservationIgnored private var overlay: SafariSetupOverlayPanel? = nil

    // Persisted preferences
    @ObservationIgnored @AppStorage("safari.autoReenable") var autoReenable = false
    @ObservationIgnored @AppStorage("safari.jsControl") var jsControlEnabled = false
    @ObservationIgnored private var launchObserver: NSObjectProtocol? = nil

    let extensionName = "RamPart"
    var accessibilityGranted: Bool { SafariAXDriver.isTrusted }

    init() { if autoReenable { startLaunchWatcher() } ; if jsControlEnabled { jsControl.start(model: self) } }

    // MARK: Main button

    func start() {
        guard !phase.isActive else { return }
        guard SafariAXDriver.isTrusted else { phase = .needsAccessibility; return }
        task = Task { await run(fullSetup: true) }
    }

    func cancel() { task?.cancel(); task = nil; overlay?.close(); overlay = nil; phase = .cancelled }

    func requestAccessibility() { SafariAXDriver.openAccessibilitySettings() }

    /// Runs the planner against Safari's live AX tree and executes the steps, re-planning after each one.
    private func run(fullSetup: Bool) async {
        phase = .launching
        showOverlay()
        defer { overlay?.close(); overlay = nil }
        do {
            let app = try await SafariAXDriver.launchSafari()
            let pid = app.processIdentifier
            let matcher = AXTreeMatcher()
            var plan = SafariSetupPlanner.plan(tree: SafariAXDriver.snapshot(pid: pid), extensionName: extensionName, wantJSFromAppleEvents: jsControlEnabled)
            if !fullSetup { plan.steps = plan.steps.filter { $0.target == "Allow Unsigned Extensions" || $0.kind == .waitForPasswordSheet || $0.kind == .pressCheckbox } }
            planNotes = plan.notes
            var done = 0
            let total = max(plan.steps.count, 1)
            while let step = plan.steps.first {
                try Task.checkCancellation()
                phase = .running(step: step.target, index: done + 1, total: total)
                try await perform(step, pid: pid, matcher: matcher)
                done += 1
                // Re-plan from the real state so each press is verified and we never toggle twice.
                try await Task.sleep(nanoseconds: 600_000_000)
                var next = SafariSetupPlanner.plan(tree: SafariAXDriver.snapshot(pid: pid), extensionName: extensionName, wantJSFromAppleEvents: jsControlEnabled)
                if !fullSetup { next.steps = next.steps.filter { $0.target == "Allow Unsigned Extensions" || $0.kind == .waitForPasswordSheet || $0.kind == .pressCheckbox } }
                if next.steps.first == step { throw SafariAXError.pressFailed(step.target) }   // pressed but nothing changed
                plan = next
            }
            phase = .done(summary: done == 0 ? "Safari was already set up." : "Safari is set up. RamPart Web Protection is on in Safari.")
            if fullSetup, autoReenable { startLaunchWatcher() }
        } catch is CancellationError { phase = .cancelled
        } catch { phase = .failed(message: error.localizedDescription) }
    }

    private func perform(_ step: SafariSetupPlanner.Step, pid: pid_t, matcher: AXTreeMatcher) async throws {
        switch step.kind {
        case .pressCheckbox:
            // Settings › Advanced › Show features for web developers
            try await openSettingsPane("Advanced", pid: pid, matcher: matcher)
            let box = try await SafariAXDriver.wait(pid: pid, seconds: 6, what: "the Advanced settings") { matcher.checkbox(in: $0, titleContains: "features for web developers") }
            try SafariAXDriver.press(box, name: step.target)
        case .pressMenuItem:
            let item = try await SafariAXDriver.wait(pid: pid, seconds: 6, what: "the Develop menu") { matcher.menuItem(in: $0, menu: "Develop", title: step.target) }
            try SafariAXDriver.press(item, name: step.target)
        case .waitForPasswordSheet:
            // macOS asks for an administrator password. RamPart never types it: pause the countdown and wait for the user.
            phase = .waitingForPassword
            overlay?.update(title: "Enter your password in Safari's dialog", detail: "macOS asks for your administrator password to allow unsigned extensions. RamPart waits and never sees what you type.", countdown: nil)
            _ = try? await SafariAXDriver.wait(pid: pid, seconds: 8, what: "the password dialog") { matcher.passwordSheet(in: $0) }
            try await SafariAXDriver.waitGone(pid: pid, seconds: 180, what: "the password dialog") { matcher.passwordSheet(in: $0) }
            overlay?.update(title: "Setting up Safari", detail: "Don't touch the mouse or keyboard for a few seconds.", countdown: 10)
        case .pressExtensionCheckbox:
            try await openSettingsPane("Extensions", pid: pid, matcher: matcher)
            let box = try await SafariAXDriver.wait(pid: pid, seconds: 8, what: "the RamPart extension in Settings › Extensions") { matcher.extensionCheckbox(in: $0, nameContains: self.extensionName) }
            try SafariAXDriver.press(box, name: step.target)
        case .openSettingsPane:
            try await openSettingsPane(step.target, pid: pid, matcher: matcher)
        }
    }

    private func openSettingsPane(_ pane: String, pid: pid_t, matcher: AXTreeMatcher) async throws {
        let tree = SafariAXDriver.snapshot(pid: pid)
        if matcher.toolbarButton(in: tree, title: pane) == nil {
            let settings = try await SafariAXDriver.wait(pid: pid, seconds: 5, what: "the Safari menu") { matcher.menuItem(in: $0, menu: "Safari", title: "Settings…") ?? matcher.menuItem(in: $0, menu: "Safari", title: "Preferences…") }
            try SafariAXDriver.press(settings, name: "Settings…")
        }
        let button = try await SafariAXDriver.wait(pid: pid, seconds: 6, what: "the \(pane) tab") { matcher.toolbarButton(in: $0, title: pane) }
        try SafariAXDriver.press(button, name: pane)
        try await Task.sleep(nanoseconds: 400_000_000)
    }

    private func showOverlay() {
        let p = SafariSetupOverlayPanel(onCancel: { [weak self] in self?.cancel() })
        p.update(title: "Setting up Safari", detail: "Don't touch the mouse or keyboard for about 10 seconds.", countdown: 10)
        p.show()
        overlay = p
    }

    // MARK: Re-enable on Safari launch ("Allow Unsigned Extensions" resets when Safari quits)

    func setAutoReenable(_ on: Bool) { autoReenable = on; on ? startLaunchWatcher() : stopLaunchWatcher() }

    private func startLaunchWatcher() {
        guard launchObserver == nil else { return }
        launchObserver = NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didLaunchApplicationNotification, object: nil, queue: .main) { [weak self] n in
            guard let app = n.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication, app.bundleIdentifier == SafariAXDriver.safariBundleID else { return }
            Task { @MainActor in
                guard let self, self.autoReenable, !self.phase.isActive, SafariAXDriver.isTrusted else { return }
                try? await Task.sleep(nanoseconds: 2_500_000_000)   // let Safari finish launching
                self.task = Task { await self.run(fullSetup: false) }
            }
        }
    }
    private func stopLaunchWatcher() { if let o = launchObserver { NSWorkspace.shared.notificationCenter.removeObserver(o); launchObserver = nil } }

    // MARK: Optional lower-security mode

    let jsControl = SafariJSControl()

    /// Called only after the explicit "Advanced: lower security" confirmation.
    func setJSControl(_ on: Bool) {
        jsControlEnabled = on
        if on { jsControl.start(model: self); task = Task { await run(fullSetup: true) } }   // also flips Develop › Allow JavaScript from Apple Events
        else { jsControl.stop(); task = Task { await turnOffJSFromAppleEvents() } }
    }

    /// Turns the Develop setting off (used by the guard when a foreign sender appears, and by the toggle).
    func turnOffJSFromAppleEvents() async {
        guard SafariAXDriver.isTrusted, let app = SafariAXDriver.runningSafari() else { jsControl.lastGuardMessage = "Turn off Safari › Develop › Allow JavaScript from Apple Events yourself: RamPart can't reach Safari's menu right now."; return }
        let m = AXTreeMatcher()
        if let item = m.menuItem(in: SafariAXDriver.snapshot(pid: app.processIdentifier), menu: "Develop", title: "Allow JavaScript from Apple Events"), item.value == "1" {
            do { try SafariAXDriver.press(item, name: "Allow JavaScript from Apple Events") } catch { jsControl.lastGuardMessage = "Couldn't turn the Develop setting off automatically. Turn off Safari › Develop › Allow JavaScript from Apple Events now." }
        }
    }
}

// MARK: - Floating overlay panel (visible over full-screen Safari; Esc cancels)

final class SafariSetupOverlayPanel: NSPanel {
    private let label = NSTextField(labelWithString: "")
    private let detail = NSTextField(wrappingLabelWithString: "")
    private let count = NSTextField(labelWithString: "")
    private var timer: Timer?
    private let onCancel: () -> Void

    init(onCancel: @escaping () -> Void) {
        self.onCancel = onCancel
        super.init(contentRect: NSRect(x: 0, y: 0, width: 440, height: 170), styleMask: [.titled, .nonactivatingPanel, .hudWindow, .utilityWindow], backing: .buffered, defer: false)
        level = .screenSaver
        collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary]
        isFloatingPanel = true; hidesOnDeactivate = false; titleVisibility = .hidden; isMovableByWindowBackground = true
        let stack = NSStackView(); stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        label.font = .systemFont(ofSize: 17, weight: .semibold)
        detail.font = .systemFont(ofSize: 13); detail.textColor = .secondaryLabelColor; detail.preferredMaxLayoutWidth = 400
        count.font = .monospacedDigitSystemFont(ofSize: 28, weight: .bold)
        let cancel = NSButton(title: "Cancel (Esc)", target: self, action: #selector(cancelPressed)); cancel.keyEquivalent = "\u{1b}"
        let row = NSStackView(views: [count, NSView(), cancel]); row.orientation = .horizontal; row.distribution = .fill
        stack.addArrangedSubview(label); stack.addArrangedSubview(detail); stack.addArrangedSubview(row)
        contentView?.addSubview(stack)
        NSLayoutConstraint.activate([stack.leadingAnchor.constraint(equalTo: contentView!.leadingAnchor, constant: 20), stack.trailingAnchor.constraint(equalTo: contentView!.trailingAnchor, constant: -20), stack.topAnchor.constraint(equalTo: contentView!.topAnchor, constant: 18), stack.bottomAnchor.constraint(lessThanOrEqualTo: contentView!.bottomAnchor, constant: -16), row.widthAnchor.constraint(equalTo: stack.widthAnchor)])
    }
    func show() { center(); if let s = NSScreen.main { setFrameOrigin(NSPoint(x: s.visibleFrame.midX - 220, y: s.visibleFrame.maxY - 220)) }; orderFrontRegardless() }
    func update(title: String, detail d: String, countdown: Int?) {
        label.stringValue = title; detail.stringValue = d
        timer?.invalidate()
        if let c = countdown {
            var n = c; count.stringValue = "\(n)"
            timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] t in n -= 1; self?.count.stringValue = n > 0 ? "\(n)" : "…"; if n <= 0 { t.invalidate() } }
        } else { count.stringValue = "⏸" }
    }
    @objc private func cancelPressed() { onCancel() }
    override func cancelOperation(_ sender: Any?) { onCancel() }
    override var canBecomeKey: Bool { true }
    override func close() { timer?.invalidate(); super.close() }
}

// MARK: - "Safari JavaScript control" mode: inject the scanner through Apple Events and guard the setting

@MainActor
@Observable
final class SafariJSControl {
    struct GuardFinding: Identifiable, Hashable { let id = UUID(); let date: Date; let finding: SafariScriptGuard.Finding; var revoked = false }
    private(set) var running = false
    private(set) var lastVerdict: String = ""
    private(set) var pagesScanned = 0
    private(set) var findings: [GuardFinding] = []
    var lastGuardMessage: String? = nil
    @ObservationIgnored private var scanTimer: Timer?
    @ObservationIgnored private var sweepTimer: Timer?
    @ObservationIgnored private var logProcess: Process?
    @ObservationIgnored private var lastURL = ""
    @ObservationIgnored private weak var model: SafariSetupModel?
    @ObservationIgnored private let service = WebVerdictService(bridge: IPCDaemonBridge())
    @ObservationIgnored private let guardLogic = SafariScriptGuard()
    @ObservationIgnored private var seenFindings = Set<String>()
    @ObservationIgnored private let scannerJS: String = (try? String(contentsOfFile: Bundle.main.path(forResource: "scanner", ofType: "js") ?? "", encoding: .utf8)) ?? ""
    @ObservationIgnored private let bannerJS: String = (try? String(contentsOfFile: Bundle.main.path(forResource: "banner", ofType: "js") ?? "", encoding: .utf8)) ?? ""

    func start(model: SafariSetupModel) {
        guard !running else { return }
        self.model = model; running = true; lastGuardMessage = nil
        // 1. Sender control: existing grants (needs Full Disk Access to read TCC.db; silently skipped otherwise) + live log watch.
        auditTCCDatabase()
        startLogWatch()
        // 2. Process watch: lightweight sweep of osascript/JXA argv every 5 s.
        sweepTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in Task { @MainActor in self?.sweepProcesses() } }
        // 3. Scan the front tab every 3 s (only when the URL changed or a scan is due).
        scanTimer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in Task { @MainActor in self?.scanFrontTab() } }
    }
    func stop() {
        running = false
        scanTimer?.invalidate(); sweepTimer?.invalidate(); scanTimer = nil; sweepTimer = nil
        logProcess?.terminate(); logProcess = nil
    }

    // Apple Events to Safari: only while the user has turned this mode on.
    private func doJavaScript(_ js: String) -> String? {
        let escaped = js.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        let src = "tell application \"Safari\"\n if (count of windows) is 0 then return \"\"\n return do JavaScript \"\(escaped)\" in current tab of front window\nend tell"
        var err: NSDictionary?
        let result = NSAppleScript(source: src)?.executeAndReturnError(&err)
        if let err { lastGuardMessage = "Safari scripting failed: \(err[NSAppleScript.errorMessage] ?? "unknown"). Check Develop › Allow JavaScript from Apple Events and the Automation permission."; return nil }
        return result?.stringValue
    }

    private func scanFrontTab() {
        guard running, !scannerJS.isEmpty, SafariAXDriver.runningSafari() != nil else { return }
        guard let json = doJavaScript(scannerJS), let data = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any], let url = obj["url"] as? String else { return }
        guard url != lastURL else { return }
        lastURL = url; pagesScanned += 1
        let sigData = try? JSONSerialization.data(withJSONObject: obj["signals"] ?? [:])
        let signals = sigData.flatMap { try? JSONDecoder().decode(PageSignals.self, from: $0) }
        let tamper = obj["tamper"] as? [String]
        let resp = service.handle(NMRequest(type: .checkPage, url: url, signals: signals, tamper: tamper))
        lastVerdict = "\(resp.verdict?.title ?? "?") · \(URL(string: url)?.host ?? url)"
        if let action = resp.action, action != .allow, !bannerJS.isEmpty {
            let reasons = (try? JSONSerialization.data(withJSONObject: (resp.reasons ?? []).map { ["title": $0.title, "detail": $0.detail] })).flatMap { String(data: $0, encoding: .utf8) } ?? "[]"
            let headline = (try? JSONSerialization.data(withJSONObject: [resp.headline ?? ""])).flatMap { String(data: $0, encoding: .utf8) }.map { String($0.dropFirst().dropLast()) } ?? "\"\""
            _ = doJavaScript(bannerJS.replacingOccurrences(of: "\"__LEVEL__\"", with: "\"\(action.rawValue)\"").replacingOccurrences(of: "__HEADLINE__", with: headline).replacingOccurrences(of: "__REASONS__", with: reasons))
        }
    }

    // MARK: Guard

    private func raise(_ f: SafariScriptGuard.Finding) {
        let key = f.detail
        guard seenFindings.insert(key).inserted else { return }
        findings.insert(GuardFinding(date: Date(), finding: f), at: 0)
        lastGuardMessage = "Another app can script Safari pages: \(f.bundleID ?? f.processPath ?? "unknown"). RamPart turned the lower-security mode off."
        // Switch the mode off immediately.
        model?.jsControlEnabled = false
        stop()
        Task { await model?.turnOffJSFromAppleEvents() }
        NotificationCenter.default.post(name: .rampartSafariGuardFinding, object: guardLogic.detection(for: f))
    }

    private func auditTCCDatabase() {
        let path = NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db"
        guard FileManager.default.isReadableFile(atPath: path) else { return }   // needs Full Disk Access
        var db: OpaquePointer?
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else { return }
        defer { sqlite3_close(db) }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT service, client, auth_value, indirect_object_identifier FROM access WHERE service = 'kTCCServiceAppleEvents'", -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }
        var rows: [SafariScriptGuard.TCCRow] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let s = String(cString: sqlite3_column_text(stmt, 0)), c = String(cString: sqlite3_column_text(stmt, 1))
            let v = Int(sqlite3_column_int(stmt, 2))
            let io = sqlite3_column_text(stmt, 3).map { String(cString: $0) }
            rows.append(.init(service: s, client: c, authValue: v, indirectObject: io))
        }
        for client in guardLogic.foreignSafariAutomators(rows) {
            raise(SafariScriptGuard.Finding(source: .tccDatabase, bundleID: client, processPath: nil, detail: "\(client) already holds permission to control Safari (found in the Automation grants).", severity: .high))
        }
    }

    private func startLogWatch() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/log")
        p.arguments = ["stream", "--style", "ndjson", "--predicate", "subsystem == \"com.apple.TCC\" AND eventMessage CONTAINS \"kTCCServiceAppleEvents\""]
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = FileHandle.nullDevice
        let buffer = LineBuffer()
        pipe.fileHandleForReading.readabilityHandler = { [weak self] h in
            for line in buffer.append(h.availableData) {
                guard let ev = SafariScriptGuard.parseLogLine(line) else { continue }
                Task { @MainActor in guard let self, let f = self.guardLogic.evaluate(event: ev) else { return }; self.raise(f) }
            }
        }
        do { try p.run(); logProcess = p } catch { lastGuardMessage = "Couldn't watch the system log for Automation requests (\(error.localizedDescription))." }
    }

    private func sweepProcesses() {
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/bin/ps"); p.arguments = ["-axo", "pid=,ppid=,uid=,args="]
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { return }
        let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        p.waitUntilExit()
        for line in out.split(separator: "\n") {
            let parts = line.trimmingCharacters(in: .whitespaces).split(separator: " ", maxSplits: 3, omittingEmptySubsequences: true)
            guard parts.count == 4, let pid = Int32(parts[0]), let ppid = Int32(parts[1]), let uid = UInt32(parts[2]) else { continue }
            let args = parts[3].split(separator: " ").map(String.init)
            guard let path = args.first, SafariScriptGuard.commandTargetsSafariJS(path: path, args: args) else { continue }
            let info = ProcessInfoLite(pid: pid, ppid: ppid, path: path, args: args, uid: uid)
            let parentID = ppid == ProcessInfo.processInfo.processIdentifier ? Bundle.main.bundleIdentifier : nil
            if let f = guardLogic.evaluate(exec: info, parentSigningID: parentID) { raise(f) }
        }
    }

    /// Runs `tccutil reset AppleEvents <bundle-id>` on the user's explicit click.
    func revoke(_ gf: GuardFinding) {
        guard let id = gf.finding.bundleID else { return }
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/tccutil"); p.arguments = ["reset", "AppleEvents", id]
        try? p.run(); p.waitUntilExit()
        if let i = findings.firstIndex(of: gf) { findings[i].revoked = p.terminationStatus == 0 }
    }
}

/// Thread-safe line splitter for the log pipe.
final class LineBuffer: @unchecked Sendable {
    private var data = Data(); private let lock = NSLock()
    func append(_ d: Data) -> [String] {
        lock.lock(); defer { lock.unlock() }
        data += d; var out: [String] = []
        while let nl = data.firstIndex(of: 0x0A) { out.append(String(decoding: data[..<nl], as: UTF8.self)); data.removeSubrange(...nl) }
        return out
    }
}

extension Notification.Name { static let rampartSafariGuardFinding = Notification.Name("app.rampart.safariGuardFinding") }
