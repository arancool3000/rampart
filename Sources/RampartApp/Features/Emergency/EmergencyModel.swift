import Foundation
import Observation
import RampartShared
import RampartGuard

/// Shared lockdown state for the Emergency screen, the app-wide banner and the menu bar. Polls every 5 s while
/// something on screen observes it (start/stop), and runs the session-side lockdown steps once.
@MainActor
@Observable
final class EmergencyModel {
    static let shared = EmergencyModel()

    var status: EmergencyStatus?
    var unsupported = false
    var error: String?
    /// The last failed action (lift, restore internet, kill switch) in plain words. Unlike `error` (the last poll), it is
    /// not cleared by the next status poll: it stays until the user dismisses it or the same action succeeds.
    var actionError: String?
    var busy = false
    var wifiMessage: String?
    var copied = false
    /// The service didn't answer the last poll. With a network lockdown last seen active, the screen shows the sudo command.
    var unreachable = false
    var killSwitchReport: String?
    var fetchedAt = Date()
    var now = Date()
    @ObservationIgnored private var poll: Timer?
    @ObservationIgnored private var ticker: Timer?
    @ObservationIgnored private var observers = 0
    @ObservationIgnored private var alwaysOn = false

    var active: Bool { status?.state.active ?? false }
    var escalated: Bool { status?.escalation != nil }
    var networkBlocked: Bool { active && (status?.state.isNetworkBlocked ?? false) }
    /// Live countdown for an automatic network block (nil = none / kept / manual).
    var secondsLeft: Int? {
        guard networkBlocked, let s = status?.networkSecondsLeft else { return nil }
        return max(0, s - Int(now.timeIntervalSince(fetchedAt)))
    }
    var countdownText: String? { secondsLeft.map { String(format: "%d:%02d", $0 / 60, $0 % 60) } }
    /// Dead-man safety: the network was blocked last time we heard from the service, and now it doesn't answer.
    var showSudoEscape: Bool { unreachable && (networkBlocked || UserDefaults.standard.bool(forKey: Self.lastBlockedKey)) }
    static let lastBlockedKey = "emergency.lastSeenNetworkBlocked"
    var killSwitchVisible: Bool {
        KillSwitch.buttonVisible(lockdownActive: active, networkBlocked: networkBlocked,
                                 webProtectionOn: AppModel.shared.status.webProtectionOn, daemonReachable: !unreachable)
    }

    /// Called once the app is connected: lockdown status is watched for the whole app lifetime (not only while the
    /// Emergency screen or banner is on screen), so a lockdown always notifies.
    func startAlways() {
        guard !alwaysOn else { return }
        alwaysOn = true
        start()
    }

    func start() {
        observers += 1
        guard poll == nil else { return }
        Task { await refresh() }
        poll = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { _ in Task { @MainActor in await EmergencyModel.shared.refresh() } }
        ticker = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in
            MainActor.assumeIsolated { let m = EmergencyModel.shared; if m.networkBlocked { m.now = Date() }; m.updateBadge() }
        }
    }
    func stop() {
        observers = max(0, observers - 1)
        if observers == 0 && !alwaysOn { poll?.invalidate(); poll = nil; ticker?.invalidate(); ticker = nil }
    }

    private var client: DaemonClient { AppModel.shared.client }

    private func apply(_ o: EmergencyBridge.Outcome) async {
        switch o {
        case .status(let s):
            let old = status
            status = s; unsupported = false; error = nil; unreachable = false; fetchedAt = Date(); now = fetchedAt
            UserDefaults.standard.set(s.state.active && s.state.isNetworkBlocked, forKey: Self.lastBlockedKey)
            if let n = EmergencyNotice.transition(from: old, to: s), old != nil || s.state.active { Notifier.shared.lockdown(n) }
            updateBadge()
            let done = EmergencyAppActions.perform(s)
            if !done.isEmpty, case .status(let s2) = await EmergencyBridge.ack(client: client, ids: done) { status = s2 }
        case .unsupported: unsupported = true
        case .error(let e): error = e; unreachable = true
        }
    }

    /// Red menu bar state with a minute countdown for an automatic network block.
    func updateBadge() {
        ChromeState.shared.setLockdownBadge(active ? (secondsLeft.map { "\(max(1, ($0 + 59) / 60))m" } ?? "") : nil)
    }

    /// Status pushed by the service the moment a lockdown starts, changes or ends (subscribeEvents stream).
    func receivePush(_ d: Data) { Task { await apply(EmergencyBridge.decode(d)) } }

    func refresh() async {
        guard AppModel.shared.mode == .live else {
            unsupported = AppModel.shared.mode != .demo
            if AppModel.shared.mode == .offline { unreachable = true }
            return
        }
        await apply(await EmergencyBridge.fetch(client: client))
    }

    func engage(note: String = "") async {
        busy = true; defer { busy = false }
        await apply(await EmergencyBridge.engage(client: client, note: note))
    }

    func rescan() async {
        busy = true; defer { busy = false }
        await apply(await EmergencyBridge.rescan(client: client))
    }

    func dismissActionError() { actionError = nil }

    /// Runs one admin-authenticated action: a fresh prompt and token every time; a failure is kept in `actionError`.
    private func adminAction(_ what: String, failurePrefix: String, _ call: @escaping (String) async -> EmergencyBridge.Outcome) async {
        busy = true; defer { busy = false }
        let o = await EmergencyBridge.withAdminToken(client: client, purpose: what, call)
        switch o {
        case .status: actionError = nil; await apply(o)
        case .unsupported: actionError = "\(failurePrefix): this version of the \(Product.name) service doesn't support it."
        case .error(let e): actionError = Self.explain(e, prefix: failurePrefix)
        }
    }

    /// Plain words for the service's refusal, with the way out.
    static func explain(_ e: String, prefix: String) -> String {
        let l = e.lowercased()
        var hint = ""
        if l.contains("token") && (l.contains("expired") || l.contains("invalid")) { hint = " Press the button again: each try asks again and gets a new approval." }
        else if l.contains("authentication") || l.contains("authorization") || l.contains("permission denied") { hint = " Press the button again to get a new administrator prompt (Touch ID or password)." }
        return "\(prefix): \(e).\(hint) If it keeps failing, use Super Kill Switch or run \(EmergencyStatus.sudoEscape) in Terminal."
    }

    /// Admin prompt + fresh token, then lift. `force` = lift before every check passed (still needs the admin password).
    func lift(force: Bool) async {
        let c = client
        await adminAction("lift Emergency Lockdown", failurePrefix: "Couldn't lift lockdown") { await EmergencyBridge.lift(client: c, token: $0, force: force) }
    }

    /// "Restore internet now": admin prompt, then the network block goes. No readiness gate.
    func restoreInternet() async {
        let c = client
        await adminAction("restore the internet", failurePrefix: "Couldn't restore the internet") { await EmergencyBridge.restoreNetwork(client: c, token: $0) }
    }

    func keepBlocking() async {
        busy = true; defer { busy = false }
        await apply(await EmergencyBridge.keepBlocking(client: client))
    }

    /// Super Kill Switch. Touch ID (or the Mac password), then path A (service, 3 s) or path B (bundled script).
    func killSwitch() async {
        busy = true; defer { busy = false }
        let noPriv = ProcessInfo.processInfo.environment["RAMPART_NO_PRIVILEGED_TOOLS"] == "1"
        if !noPriv { guard await KillSwitchAuth.confirm() else { actionError = "Super Kill Switch cancelled. Nothing was changed."; return } }
        // Wi-Fi auto-disconnect lives in the app.
        var w = PublicWiFiHost.shared.guardian.settings; w.disconnectInsecureWiFi = false; PublicWiFiHost.shared.guardian.settings = w
        if AppModel.shared.mode == .live, !noPriv {
            let c = client
            var report: KillSwitch.Report?
            _ = await EmergencyBridge.withAdminToken(client: c, purpose: "turn off everything \(Product.name) is doing to your network") { token in
                if case .success(let r) = await EmergencyBridge.killSwitch(client: c, token: token) { report = r }
                return .unsupported
            }
            if let r = report {
                actionError = nil
                killSwitchReport = r.summary + "\n" + r.steps.map { "\($0.ok ? "✓" : "✗") \($0.title)" }.joined(separator: "\n")
                await refresh(); return
            }
        }
        guard let script = KillSwitchScript.locate() else {
            killSwitchReport = "The service didn't answer and the kill switch script isn't available in this copy. In Terminal run: sudo rampart killswitch"
            return
        }
        let r = KillSwitchScript.run(script: script, dryRun: noPriv)
        killSwitchReport = (r.ok ? "" : "The administrator prompt was cancelled or the script failed. In Terminal run: sudo rampart killswitch\n") + r.output
        await refresh()
    }

    func turnWiFiOff() { wifiMessage = EmergencyAppActions.turnWiFiOff() ?? "Wi-Fi is off." }

    func copyReport() {
        guard let r = status?.report else { return }
        EmergencyAppActions.copy(r)
        copied = true
        Task { try? await Task.sleep(nanoseconds: 2_000_000_000); copied = false }
    }
}

/// Calm, honest copy in one place.
enum EmergencyCopy {
    static let intro = "If something dangerous is running, Emergency Lockdown isolates this Mac in seconds: it freezes the program, quarantines its files, cuts the network, locks your passwords and blocks remote access. Your own apps keep working."
    static let auto = "Turns on by itself only for confirmed, critical threats, and cuts the internet by itself only for an active attack (ransomware, or data being sent out by malware, or two independent signals). Never for health issues like a missing permission, notes, test files or things you've allowed."
    static let stays = "Lift it any time with your administrator password; the checklist below is advice, not a lock. An automatic network block ends by itself after 10 minutes and never comes back after a restart. If the app can't reach the service, run \(EmergencyStatus.sudoEscape) in Terminal."
    static let limits = "Without Apple's Endpoint Security entitlement \(Product.name) acts right after a program starts, not before. Network containment and process freezing need the installed system service; in other modes each step is recorded but not carried out."
}
