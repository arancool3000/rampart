import Foundation
import SwiftUI
import RampartShared
import RampartNetwork
import RampartVault

/// App Firewall + content filter + privacy report, all through IPC `.netGuard(Data)`.
@MainActor
@Observable
final class NetGuardModel {
    static let shared = NetGuardModel()

    var status: NetGuardStatus?
    var error: String?
    var busy = false
    var unsupported = false
    /// Prompts pushed by the service (shown in-app as a banner, and posted as a notification).
    var prompts: [FirewallPrompt] = []
    var lastPlan: AppBlockPlan?
    @ObservationIgnored private var notified = Set<String>()
    @ObservationIgnored private var poll: Task<Void, Never>?

    private var client: DaemonClient { AppModel.shared.client }

    private func send(_ cmd: NetGuardCommand) async -> NetGuardStatus? {
        guard !Headless.active else { return nil }
        do {
            switch try await client.request(.netGuard(cmd.encoded()), timeout: 15) {
            case .netGuard(let d):
                let st = try JSONDecoder.rampart.decode(NetGuardStatus.self, from: d)
                status = st; error = nil; unsupported = false
                mergePrompts(st.firewall.prompts, replace: true)
                if let p = st.plan { lastPlan = p }
                return st
            case .error(let e):
                if e.localizedCaseInsensitiveContains("unknown request") || e.localizedCaseInsensitiveContains("not available") { unsupported = true }
                error = e
            default: unsupported = true
            }
        } catch { self.error = "RamPart's protection service isn't answering: \(error.localizedDescription)" }
        return nil
    }

    func refresh() async { _ = await send(NetGuardCommand(op: .status)) }

    /// Polls every 5 s while a NetGuard screen is visible.
    func startPolling() {
        poll?.cancel()
        poll = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(nanoseconds: 5_000_000_000)
            }
        }
    }
    func stopPolling() { poll?.cancel(); poll = nil }

    func decide(_ key: String, _ d: FirewallDecision) async {
        busy = true; defer { busy = false }
        prompts.removeAll { $0.key == key }
        AppModel.shared.noteActivityActor(place: "App Firewall")
        _ = await send(NetGuardCommand(op: .firewallDecide, key: key, decision: d))
    }
    func forget(_ key: String) async {
        busy = true; defer { busy = false }
        _ = await send(NetGuardCommand(op: .firewallForget, key: key))
    }
    func plan(_ key: String) async { lastPlan = nil; _ = await send(NetGuardCommand(op: .plan, key: key)) }

    func setFilter(_ c: ContentFilterConfig) async {
        busy = true; defer { busy = false }
        AppModel.shared.noteActivityActor(place: "Content filter")
        _ = await send(NetGuardCommand(op: .filterSet, config: c))
    }

    private func mergePrompts(_ ps: [FirewallPrompt], replace: Bool) {
        if replace { prompts = ps } else { for p in ps where !prompts.contains(where: { $0.key == p.key }) { prompts.append(p) } }
    }

    /// `.netGuard(Data)` pushed over subscribeEvents: JSON of NetGuardPush.
    func receivePush(_ d: Data) {
        guard let push = try? JSONDecoder.rampart.decode(NetGuardPush.self, from: d) else { return }
        mergePrompts(push.prompts, replace: false)
        for p in push.prompts where notified.insert(p.key).inserted {
            Notifier.shared.post(.network, title: "\(SafeText.line(p.name, max: 60)) wants to connect to the internet",
                                 body: "\(p.signerLabel) app reaching \(SafeText.line(p.host ?? p.address, max: 80)). Open RamPart > App Firewall to Allow or Block it.",
                                 critical: true, userInfo: ["route": "appFirewall"])
        }
    }
}

/// Periodic breach monitoring: vault passwords (k-anonymity, existing BreachMonitor) every 6 hours while the vault is
/// unlocked, plus the optional HIBP email check with the user's own API key once a day.
@MainActor
@Observable
final class BreachWatch {
    static let shared = BreachWatch()
    static let keyService = "app.rampart.breach.hibp", keyAccount = "hibp-api-key"

    var emails: [String] = []
    var results: [String: EmailBreachResult] = [:]
    var hasKey = false
    var checking = false
    var message: String?
    @ObservationIgnored private var timer: Timer?
    @ObservationIgnored private let defaults = UserDefaults.standard

    private var storeURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("RamPart", isDirectory: true).appendingPathComponent("email-breaches.json")
    }
    private struct Saved: Codable { var emails: [String]; var results: [String: EmailBreachResult] }

    func start() {
        guard timer == nil, !Headless.active else { return }
        load()
        hasKey = defaults.bool(forKey: "breach.hibp.hasKey")
        timer = Timer.scheduledTimer(withTimeInterval: 6 * 3600, repeats: true) { _ in
            Task { @MainActor in BreachWatch.shared.tick() }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 120) { BreachWatch.shared.tick() }
    }

    func tick() {
        PasswordsModel.shared.startBreachSweep(force: false)   // no-op while the vault is locked or results are fresh
        if hasKey, emails.contains(where: { HIBPEmailClient.isDue(results[$0]) }) { Task { await checkEmails(force: false) } }
    }

    private func load() {
        guard let d = try? Data(contentsOf: storeURL), let s = try? JSONDecoder.rampart.decode(Saved.self, from: d) else { return }
        emails = s.emails; results = s.results
    }
    private func save() {
        try? FileManager.default.createDirectory(at: storeURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        if let d = try? JSONEncoder.rampart.encode(Saved(emails: emails, results: results)) { try? d.write(to: storeURL, options: [.atomic, .completeFileProtection]) }
    }

    func setKey(_ key: String) {
        let k = key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard HIBPEmailClient.isPlausibleKey(k) else { message = "That doesn't look like a Have I Been Pwned API key."; return }
        do {
            try Keychain.setGeneric(service: Self.keyService, account: Self.keyAccount, data: Data(k.utf8), label: "RamPart breach monitor (HIBP)")
            hasKey = true; defaults.set(true, forKey: "breach.hibp.hasKey"); message = "Key saved in your login Keychain."
        } catch { message = "Couldn't save the key: \(error.localizedDescription)" }
    }
    func removeKey() {
        _ = Keychain.deleteGeneric(service: Self.keyService, account: Self.keyAccount)
        hasKey = false; defaults.set(false, forKey: "breach.hibp.hasKey"); message = "Key removed."
    }

    func add(_ email: String) {
        let e = email.trimmingCharacters(in: .whitespaces).lowercased()
        guard HIBPEmailClient.isValidEmail(e) else { message = EmailBreachError.invalidEmail.description; return }
        if !emails.contains(e) { emails.append(e); save() }
        if hasKey { Task { await checkEmails(force: true, only: e) } }
    }
    func remove(_ email: String) { emails.removeAll { $0 == email }; results[email] = nil; save() }

    func checkEmails(force: Bool, only: String? = nil) async {
        guard hasKey, !checking, !Headless.active else { return }
        guard let data = try? Keychain.readGeneric(service: Self.keyService, account: Self.keyAccount),
              let key = String(data: data, encoding: .utf8) else { message = EmailBreachError.noKey.description; return }
        checking = true; defer { checking = false }
        let client = HIBPEmailClient(apiKey: key)
        for e in emails where (only == nil || only == e) && (force || HIBPEmailClient.isDue(results[e])) {
            let r = await client.check(e)
            let fresh = HIBPEmailClient.newBreaches(old: results[e], new: r)
            results[e] = r
            if !fresh.isEmpty && results[e] != nil {
                Notifier.shared.post(.network, title: "\(e) appeared in \(fresh.count == 1 ? "a new breach" : "\(fresh.count) new breaches")",
                                     body: fresh.prefix(3).map(\.title).joined(separator: ", ") + ". Change that account's password.", critical: true)
            }
            if r.error != nil { message = r.error; break }
            try? await Task.sleep(nanoseconds: 6_500_000_000)   // HIBP rate limit (lowest tier: 10 per minute)
        }
        save()
    }
}
