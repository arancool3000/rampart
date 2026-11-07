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
    @ObservationIgnored private var active: [ObjectIdentifier: (download: WKDownload, id: UUID, url: URL, risky: Bool, banking: Bool, redirects: Int)] = [:]

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
        active[ObjectIdentifier(download)] = (download, item.id, dest, risky, bankingMode, 0)
        download.delegate = self
        return dest
    }

    private func update(_ id: UUID, _ f: (inout Item) -> Void) {
        if let i = items.firstIndex(where: { $0.id == id }) { f(&items[i]) }
    }

    /// Quarantine + strip exec bits, then scan via the daemon and apply the policy.
    private func finish(id: UUID, url: URL, risky: Bool, bankingMode: Bool) async {
        update(id) { $0.state = .scanning }
        // hx6: a file that couldn't be quarantined (xattr refused, file swapped for a symlink) never
        // leaves the vault: without the flag Gatekeeper would not check it when opened.
        guard Self.applyQuarantine(url) else {
            update(id) { $0.state = .held(reason: "RamPart couldn't mark this file as downloaded from the internet, so it stays in the vault. Delete it unless you expected it.", url: url) }
            return
        }
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
            guard let final = Self.release(url) else {
                update(id) { $0.state = .held(reason: "RamPart couldn't move this file to Downloads. It stays quarantined in the vault.", url: url) }
                return
            }
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
        // hx6: re-apply (and re-check) the quarantine flag right before release.
        guard Self.applyQuarantine(url), let final = Self.release(url) else { return }
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

    /// Sets `com.apple.quarantine` and 0600 on a regular file, through one descriptor opened with
    /// O_NOFOLLOW so a symlink planted in the vault can't redirect either change. Returns false unless
    /// the flag reads back. (hx6)
    @discardableResult
    nonisolated static func applyQuarantine(_ url: URL, date: Date = Date()) -> Bool {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return false }
        let value = DownloadPolicy.quarantineAttribute(date: date)
        let set = value.withCString { fsetxattr(fd, "com.apple.quarantine", $0, strlen($0), 0, 0) }
        guard set == 0 else { return false }
        guard fchmod(fd, 0o600) == 0 else { return false }
        let n = fgetxattr(fd, "com.apple.quarantine", nil, 0, 0, 0)
        return n > 0
    }

    /// Moves a vault file into ~/Downloads under a name that doesn't exist yet. Uses renamex_np with
    /// RENAME_EXCL so an existing file or a symlink planted under that name is never replaced, and
    /// returns nil (file stays in the vault) if the move can't be done safely. (hx6)
    nonisolated static func release(_ url: URL, downloads explicitDir: URL? = nil) -> URL? {
        let downloads = explicitDir ?? FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Downloads")
        let name = DownloadPolicy.safeFilename(url.lastPathComponent)
        let base = (name as NSString).deletingPathExtension, ext = (name as NSString).pathExtension
        for n in 1...200 {
            let candidate = n == 1 ? name : (ext.isEmpty ? "\(base) \(n)" : "\(base) \(n).\(ext)")
            let dest = downloads.appendingPathComponent(candidate)
            let r = url.path.withCString { src in dest.path.withCString { dst in renamex_np(src, dst, UInt32(RENAME_EXCL)) } }
            if r == 0 {
                try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
                return dest
            }
            if errno != EEXIST { return nil }
        }
        return nil
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
        // hx6: Banking mode applies if it was on when the download started OR is on now.
        let banking = a.banking || BrowserModel.shared.bankingMode
        Task { await finish(id: a.id, url: a.url, risky: a.risky, bankingMode: banking) }
    }
    func download(_ download: WKDownload, didFailWithError error: Error, resumeData: Data?) {
        guard let a = active.removeValue(forKey: ObjectIdentifier(download)) else { return }
        update(a.id) { $0.state = .failed(error.localizedDescription) }
        try? FileManager.default.removeItem(at: a.url.deletingLastPathComponent())
    }
    func download(_ download: WKDownload, decidePolicyForHTTPRedirect response: HTTPURLResponse, newRequest request: URLRequest) async -> WKDownload.RedirectPolicy {
        // Redirects to plain HTTP or to a blocked host cancel the download. hx6: so do more than
        // DownloadPolicy.maxRedirects hops; any look-alike / scam hop, or a long chain, marks the source risky.
        guard let u = request.url, u.scheme?.lowercased() == "https" else { return .cancel }
        let key = ObjectIdentifier(download)
        guard var a = active[key] else { return .cancel }
        a.redirects += 1
        let f = WebEngineAdapter.shared.facts(for: u)
        if f.blocklistHit != nil || f.scamVerdict == .likelyScam || a.redirects > DownloadPolicy.maxRedirects { return .cancel }
        if DownloadPolicy.isRiskySource(hops: [f], redirectCount: a.redirects) { a.risky = true }
        active[key] = a
        return .allow
    }
}
