import Foundation
import AppKit
import WebKit
import Observation
import RampartShared

/// Every download lands in a vault folder (`~/Library/Application Support/Rampart/BrowserDownloads`),
/// gets `com.apple.quarantine`, has its exec bits stripped, and is scanned by the daemon before it
/// is released to ~/Downloads. Nothing is revealed in Finder until the policy says so.
@MainActor
@Observable
final class DownloadManager: NSObject {
    static let shared = DownloadManager()

    enum State: Equatable {
        case downloading(Double)       // 0...1 (or -1 when unknown)
        case scanning
        case released(URL)
        case held(reason: String, url: URL)
        case blocked(reason: String, url: URL)
        case failed(String)
    }
    struct Item: Identifiable, Equatable {
        let id = UUID()
        var filename: String
        var sourceHost: String
        var cls: DownloadClass
        var bytes: Int64 = 0
        var expected: Int64 = -1
        var state: State
        var started = Date()
    }

    private(set) var items: [Item] = []
    var daemonAvailable: Bool? = nil
    let vault: URL = Paths.userRoot.appendingPathComponent("BrowserDownloads")
    @ObservationIgnored private var active: [ObjectIdentifier: (download: WKDownload, id: UUID, url: URL, risky: Bool)] = [:]

    override init() {
        super.init()
        try? FileManager.default.createDirectory(at: vault, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }

    func begin(_ download: WKDownload, suggestedFilename: String, mimeType: String?, sourceHost: String, risky: Bool, bankingMode: Bool) -> URL {
        let name = DownloadPolicy.safeFilename(suggestedFilename)
        let cls = DownloadClass.classify(filename: name, mimeType: mimeType)
        var dest = vault.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try? FileManager.default.createDirectory(at: dest, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        dest = dest.appendingPathComponent(name)
        let item = Item(filename: name, sourceHost: sourceHost, cls: cls, state: .downloading(-1))
        items.insert(item, at: 0)
        active[ObjectIdentifier(download)] = (download, item.id, dest, risky)
        download.delegate = self
        return dest
    }

    private func update(_ id: UUID, _ f: (inout Item) -> Void) {
        if let i = items.firstIndex(where: { $0.id == id }) { f(&items[i]) }
    }

    /// Quarantine + strip exec bits, then scan via the daemon and apply the policy.
    private func finish(id: UUID, url: URL, risky: Bool, bankingMode: Bool) async {
        update(id) { $0.state = .scanning }
        Self.applyQuarantine(url)
        let cls = items.first(where: { $0.id == id })?.cls ?? .other
        let outcome: ScanOutcome
        do {
            let dets = try await BrowserDaemonClient.shared.scan(path: url.path)
            daemonAvailable = true
            if let worst = dets.max(by: { $0.severity < $1.severity }), worst.severity >= .medium { outcome = .infected(name: worst.name) }
            else { outcome = .clean }
        } catch {
            daemonAvailable = false
            outcome = .unavailable
        }
        let action = DownloadPolicy(bankingMode: bankingMode).decide(class: cls, outcome: outcome, fromRiskySite: risky)
        switch action {
        case .release:
            let final = Self.release(url)
            update(id) { $0.state = .released(final) }
        case .holdForConfirmation(let reason):
            update(id) { $0.state = .held(reason: reason, url: url) }
        case .blocked(let reason):
            update(id) { $0.state = .blocked(reason: reason, url: url) }
        }
    }

    /// User confirmed a held item: move to ~/Downloads (quarantine flag stays, Gatekeeper still runs).
    func releaseHeld(_ id: UUID) {
        guard let item = items.first(where: { $0.id == id }), case .held(_, let url) = item.state else { return }
        let final = Self.release(url)
        update(id) { $0.state = .released(final) }
    }
    func delete(_ id: UUID) {
        guard let item = items.first(where: { $0.id == id }) else { return }
        switch item.state {
        case .held(_, let u), .blocked(_, let u): try? FileManager.default.removeItem(at: u.deletingLastPathComponent())
        default: break
        }
        items.removeAll { $0.id == id }
    }
    func reveal(_ id: UUID) {
        guard let item = items.first(where: { $0.id == id }), case .released(let u) = item.state else { return }
        NSWorkspace.shared.activateFileViewerSelecting([u])
    }

    static func applyQuarantine(_ url: URL) {
        let value = DownloadPolicy.quarantineAttribute()
        _ = value.withCString { setxattr(url.path, "com.apple.quarantine", $0, strlen($0), 0, 0) }
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    static func release(_ url: URL) -> URL {
        let downloads = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Downloads")
        var dest = downloads.appendingPathComponent(url.lastPathComponent)
        var n = 2
        let base = url.deletingPathExtension().lastPathComponent, ext = url.pathExtension
        while FileManager.default.fileExists(atPath: dest.path) {
            dest = downloads.appendingPathComponent(ext.isEmpty ? "\(base) \(n)" : "\(base) \(n).\(ext)"); n += 1
        }
        do { try FileManager.default.moveItem(at: url, to: dest) } catch { return url }
        try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
        return dest
    }
}

extension DownloadManager: WKDownloadDelegate {
    func download(_ download: WKDownload, decideDestinationUsing response: URLResponse, suggestedFilename: String) async -> URL? {
        // Destination was fixed in begin(); WebKit requires we answer here.
        guard let a = active[ObjectIdentifier(download)] else { return nil }
        update(a.id) { $0.expected = response.expectedContentLength }
        return a.url
    }
    func downloadDidFinish(_ download: WKDownload) {
        guard let a = active.removeValue(forKey: ObjectIdentifier(download)) else { return }
        let banking = BrowserModel.shared.bankingMode
        Task { await finish(id: a.id, url: a.url, risky: a.risky, bankingMode: banking) }
    }
    func download(_ download: WKDownload, didFailWithError error: Error, resumeData: Data?) {
        guard let a = active.removeValue(forKey: ObjectIdentifier(download)) else { return }
        update(a.id) { $0.state = .failed(error.localizedDescription) }
        try? FileManager.default.removeItem(at: a.url.deletingLastPathComponent())
    }
    func download(_ download: WKDownload, decidePolicyForHTTPRedirect response: HTTPURLResponse, newRequest request: URLRequest) async -> WKDownload.RedirectPolicy {
        // Redirects to plain HTTP or to a blocked host cancel the download.
        guard let u = request.url, u.scheme?.lowercased() == "https" else { return .cancel }
        return WebEngineAdapter.shared.facts(for: u).blocklistHit == nil ? .allow : .cancel
    }
}
