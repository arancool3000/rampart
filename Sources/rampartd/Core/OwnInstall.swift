import Foundation
import RampartShared
import RampartGuard

/// RamPart's own installed files and processes, verified (see RampartGuard/OwnInstallTrust.swift). RamPart never
/// quarantines, kills, freezes or pauses these, and a legitimate install / upgrade of them is never tampering.
enum OwnInstall {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var cached: (date: Date, hashes: Set<String>)?

    /// Trusted cdhashes (own binary, install identity, client pins), refreshed every 2 minutes so an upgrade's new
    /// identity record is picked up.
    static func trustedCDHashes() -> Set<String> {
        lock.lock(); defer { lock.unlock() }
        if let c = cached, Date().timeIntervalSince(c.date) < 120 { return c.hashes }
        let h = OwnInstallTrust.currentCDHashes(supportRoot: GuardPaths.standard.supportRoot)
        cached = (Date(), h)
        return h
    }
    static func invalidate() { lock.lock(); cached = nil; lock.unlock() }

    /// Trust for the real install layout plus, when different, the guardian's layout (scratch in dev / user mode).
    static func trusts(_ guardian: GuardService?) -> [OwnInstallTrust] {
        let hashes = trustedCDHashes()
        var out = [OwnInstallTrust(paths: .standard, manifest: guardian?.manifest, trustedCDHashes: hashes)]
        if let g = guardian, g.paths != .standard { out.append(OwnInstallTrust(paths: g.paths, manifest: g.manifest, trustedCDHashes: hashes)) }
        return out
    }

    static func isVerifiedOwnFile(_ path: String, guardian: GuardService?) -> Bool {
        trusts(guardian).contains { $0.isVerifiedOwnFile(path) }
    }
    static func isVerifiedOwnFile(_ path: String, _ p: Protection) -> Bool { isVerifiedOwnFile(path, guardian: p.services.guardian) }

    /// Names one of RamPart's own install locations (verified or not).
    static func isOwnPath(_ path: String, _ p: Protection) -> Bool {
        trusts(p.services.guardian).contains { $0.paths.isProtected(path) || $0.paths.isPlist(path) }
    }

    /// The running process `pid` is one of our verified executables.
    static func isVerifiedOwnProcess(pid: Int32, _ p: Protection) -> Bool {
        guard pid > 0, let exe = ProcessPath.of(pid) else { return false }
        return trusts(p.services.guardian).contains { $0.isVerifiedOwnExecutable(exe) }
    }
}

enum ProcessPath {
    static func of(_ pid: Int32) -> String? {
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let n = proc_pidpath(pid, &buf, UInt32(buf.count))
        return n > 0 ? String(cString: buf) : nil
    }
}
