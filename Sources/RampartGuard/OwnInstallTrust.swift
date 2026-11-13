import Foundation
import Security
import RampartShared

// User incident 2026-11-09: the daemon flagged and QUARANTINED RamPart's own /Library/LaunchAgents/app.rampart.agent.plist
// as "Tampering with RamPart: plistTamper", locked the Mac down, and after a reinstall reported "A quarantined file came
// back". RamPart's own installed files, when they verify, are never quarantined, killed or paused by RamPart.
//
// "Verified" means one of:
//   - the sealed Guard manifest pins this exact file (SHA-256 match);
//   - a launch plist with our Label whose job runs one of our exact service executables (RamPartIdentity.isOurJob) and
//     that executable verifies;
//   - an executable with a valid strict signature, a RamPart signing identifier, and either a trusted Team ID or a cdhash
//     we trust (the running daemon's own, the install identity record written by rampart-setup.sh, trusted-client pins),
//     or that ships in the same bundle as a helper whose cdhash we trust (same build as the running service).
// A look-alike (ad-hoc signed as app.rampart.*, unknown cdhash, not in the manifest) is NOT verified.

/// Signature facts of one file (static check; reads the disk only, never prompts).
public struct OwnCodeSignature: Sendable, Equatable {
    public var identifier: String
    public var teamID: String?
    public var cdhash: String
    public var valid: Bool
    public init(identifier: String, teamID: String?, cdhash: String, valid: Bool) {
        self.identifier = identifier; self.teamID = teamID; self.cdhash = cdhash; self.valid = valid
    }

    public static func read(_ path: String) -> OwnCodeSignature? {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code else { return nil }
        let valid = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), nil) == errSecSuccess
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let d = info as? [String: Any] else { return nil }
        let cd = (d[kSecCodeInfoUnique as String] as? Data).map { $0.map { String(format: "%02x", $0) }.joined() } ?? ""
        return OwnCodeSignature(identifier: d[kSecCodeInfoIdentifier as String] as? String ?? "",
                                teamID: d[kSecCodeInfoTeamIdentifier as String] as? String, cdhash: cd, valid: valid && !cd.isEmpty)
    }
}

public struct OwnInstallTrust: Sendable {
    public var paths: GuardPaths
    public var manifest: InstallManifest?
    public var trustedTeamIDs: Set<String>
    /// Lower-case hex cdhashes we trust for our own code.
    public var trustedCDHashes: Set<String>
    /// Signature reader (injectable for tests).
    public var signature: @Sendable (String) -> OwnCodeSignature?
    /// wms-o7: the real install is root-owned (rampart-setup.sh: chown -R root:wheel, chmod -R go-w). An administrator
    /// can't write into it without the password, but can rename /Applications/RamPart.app and put a copy of their own in
    /// its place (hard links keep the original files root-owned) with an extra file added. Such a file used to verify as
    /// "ours" (bundle resources trusted because the main executable verifies; any app.rampart.* signed binary trusted
    /// because the bundle's helper does), so it was never quarantined, never frozen, never a lockdown trigger, and a
    /// manifest mismatch it caused was resealed as a "verified upgrade". When `requireRootOwnership` is on, a file is
    /// vouched for only if it and every folder from it up to the bundle (or its own folder) is root-owned and not
    /// group/world-writable. Default: on for the real install layout, off for scratch (dev / test) layouts.
    public var requireRootOwnership: Bool
    /// wms-o7: the bundle's code signature (strict, resources included) validates: an added or changed file breaks it.
    /// Bundle resources and same-bundle executables are vouched for only when the bundle is sealed.
    public var bundleSealed: @Sendable (String) -> Bool
    /// Ownership rule (injectable for tests): see `requireRootOwnership`.
    public var ownerOK: @Sendable (_ path: String, _ stopAt: String) -> Bool = OwnInstallTrust.rootOwnedChain

    public init(paths: GuardPaths = .standard, manifest: InstallManifest? = nil, trustedTeamIDs: Set<String> = [],
                trustedCDHashes: Set<String> = [], signature: @escaping @Sendable (String) -> OwnCodeSignature? = OwnCodeSignature.read,
                requireRootOwnership: Bool? = nil, bundleSealed: (@Sendable (String) -> Bool)? = nil) {
        self.paths = paths; self.manifest = manifest; self.trustedTeamIDs = trustedTeamIDs
        self.trustedCDHashes = Set(trustedCDHashes.map { $0.lowercased() }); self.signature = signature
        let strict = requireRootOwnership ?? (paths == .standard)
        self.requireRootOwnership = strict
        self.bundleSealed = bundleSealed ?? (strict ? { BundleSeal.isSealed($0) } : { _ in true })
    }

    /// `path` and every folder above it up to and including `stopAt` (or just its own folder when `stopAt` isn't an
    /// ancestor): root-owned, not group/world-writable.
    public static func rootOwnedChain(_ path: String, stopAt: String) -> Bool {
        func safe(_ p: String) -> Bool {
            var st = stat()
            return lstat(p, &st) == 0 && st.st_uid == 0 && st.st_mode & 0o022 == 0
        }
        let p = GuardPaths.normalize(path), stop = GuardPaths.normalize(stopAt)
        guard safe(p) else { return false }
        var dir = (p as NSString).deletingLastPathComponent
        let chain = p.hasPrefix(stop + "/")
        var hops = 0
        while hops < 64 {
            hops += 1
            guard safe(dir) else { return false }
            if !chain || dir == stop || dir == "/" || dir.isEmpty { return true }
            dir = (dir as NSString).deletingLastPathComponent
        }
        return false
    }

    private func owned(_ path: String) -> Bool {
        guard requireRootOwnership else { return true }
        return ownerOK(path, paths.isInAppBundle(path) ? paths.appBundle : (path as NSString).deletingLastPathComponent)
    }

    /// The trust anchors of the running service: its own cdhash, the root-owned install identity record and trusted
    /// client pins under `supportRoot` (ignored unless root-owned and not group/world-writable).
    public static func currentCDHashes(supportRoot: String, executable: String = CommandLine.arguments.first ?? "") -> Set<String> {
        var out = Set<String>()
        let me = URL(fileURLWithPath: executable).resolvingSymlinksInPath().path
        if let s = OwnCodeSignature.read(me), s.valid { out.insert(s.cdhash.lowercased()) }
        func trustedFile(_ p: String) -> Data? {
            var st = stat()
            guard lstat(p, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_mode & 0o022 == 0, st.st_uid == 0,
                  st.st_size < 1 << 20 else { return nil }
            return FileManager.default.contents(atPath: p)
        }
        if let d = trustedFile(supportRoot + "/install-identity.plist"),
           let pl = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any] {
            out.formUnion(parseCDHashList((pl["appCDHash"] as? String ?? "") + "," + (pl["daemonCDHash"] as? String ?? "")))
        }
        if let d = trustedFile(supportRoot + "/trusted-clients.json"), let a = try? JSONDecoder().decode([String].self, from: d) {
            out.formUnion(a.map { $0.lowercased() }.filter(isHex40))
        }
        return out
    }

    /// "arm64=<hex>,x86_64=<hex>" (or bare hex) -> set of hex cdhashes.
    public static func parseCDHashList(_ s: String) -> Set<String> {
        Set(s.split(separator: ",").map { String($0.split(separator: "=").last ?? "").lowercased() }.filter(isHex40))
    }
    static func isHex40(_ s: String) -> Bool { s.count == 40 && s.allSatisfy(\.isHexDigit) }

    private func manifestMatches(_ path: String) -> Bool {
        guard let m = manifest else { return false }
        let n = GuardPaths.normalize(path)
        guard let key = m.entries.keys.first(where: { GuardPaths.normalize($0) == n }), let expected = m.entries[key] else { return false }
        return InstallManifest.sha256(ofFile: path) == expected
    }

    private func isOurIdentifier(_ id: String) -> Bool { id.hasPrefix(Product.bundlePrefix + ".") }

    /// One of our own executables, verified (not just named like ours).
    public func isVerifiedOwnExecutable(_ path: String) -> Bool {
        let p = GuardPaths.normalize(path)
        guard paths.isJobExecutable(p) || paths.binaries.map(GuardPaths.normalize).contains(p) || paths.isInAppBundle(p) else { return false }
        guard owned(p) else { return false }
        if manifestMatches(p) { return true }
        guard let s = signature(p), s.valid, isOurIdentifier(s.identifier) else { return false }
        if let t = s.teamID, !t.isEmpty, trustedTeamIDs.contains(t) { return true }
        if trustedCDHashes.contains(s.cdhash.lowercased()) { return true }
        // Same build as a trusted helper: a bundle executable whose bundle ships a helper we trust.
        if paths.isInAppBundle(p), bundleSealed(paths.appBundle) {
            let b = GuardPaths.normalize(paths.appBundle)
            for h in [b + "/Contents/Helpers/rampartd", b + "/Contents/MacOS/rampartd"] where h != p {
                if owned(h), let hs = signature(h), hs.valid, isOurIdentifier(hs.identifier),
                   trustedCDHashes.contains(hs.cdhash.lowercased()) || hs.teamID.map({ !$0.isEmpty && trustedTeamIDs.contains($0) }) == true {
                    return true
                }
            }
        }
        return false
    }

    /// Our launch plist whose job runs our verified executable.
    public func isVerifiedOwnPlist(_ path: String) -> Bool {
        guard paths.isPlist(path), owned(path) else { return false }
        if manifestMatches(path) { return true }
        guard RamPartIdentity.isOurPlist(path, paths: paths),
              let data = FileManager.default.contents(atPath: path),
              let pl = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { return false }
        let program = (pl["Program"] as? String) ?? (pl["ProgramArguments"] as? [String])?.first ?? ""
        return !program.isEmpty && isVerifiedOwnExecutable(program)
    }

    /// Any of RamPart's own installed files (plist, service binary, app bundle content) that verifies.
    public func isVerifiedOwnFile(_ path: String) -> Bool {
        guard path.hasPrefix("/"), FileManager.default.fileExists(atPath: path) else { return false }
        if paths.isPlist(path) { return isVerifiedOwnPlist(path) }
        if paths.isJobExecutable(path) || paths.binaries.map(GuardPaths.normalize).contains(GuardPaths.normalize(path)) {
            return isVerifiedOwnExecutable(path)
        }
        if paths.isInAppBundle(path) {
            guard owned(path) else { return false }
            if manifestMatches(path) { return true }
            // Bundle resources: the bundle's own executables must verify AND the bundle's seal must still hold (an added
            // or replaced resource breaks it; wms-o7: it used to be assumed, not checked).
            guard bundleSealed(paths.appBundle) else { return false }
            let b = GuardPaths.normalize(paths.appBundle)
            return isVerifiedOwnExecutable(b + "/Contents/MacOS/Rampart") || isVerifiedOwnExecutable(b + "/Contents/Helpers/rampartd")
        }
        return false
    }

    /// A manifest mismatch that is a legitimate install / upgrade (rampart-setup.sh install / install-from): every changed
    /// or added file verifies by signature + trusted cdhash (not by the old manifest), and only app-bundle files went
    /// missing. Such a mismatch is resealed, never reported as tampering. Symlinks and unsafe ownership never qualify.
    public func isVerifiedUpgrade(_ mismatches: [ManifestMismatch]) -> Bool {
        guard !mismatches.isEmpty else { return false }
        var fresh = self; fresh.manifest = nil
        for m in mismatches {
            switch m.kind {
            case .symlink, .unsafeOwnership: return false
            case .missing: if !paths.isInAppBundle(m.path) { return false }
            case .hashChanged, .unlisted: if !fresh.isVerifiedOwnFile(m.path) { return false }
            }
        }
        return true
    }

    /// The running process at `executable` is one of our verified executables.
    public func isVerifiedOwnProcess(executable: String) -> Bool { isVerifiedOwnExecutable(executable) }
}

/// wms-o7: strict static validation of a whole bundle (resources and nested code included). Read-only, never prompts.
/// Cached per bundle for 60 s, keyed on the inode and modification times of the bundle's sealed folders, so an added
/// file (which changes its folder's mtime) is noticed at once.
public enum BundleSeal {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var cache: [String: (key: String, at: Date, ok: Bool)] = [:]

    static func cacheKey(_ bundle: String) -> String {
        ["", "/Contents", "/Contents/MacOS", "/Contents/Resources", "/Contents/Helpers", "/Contents/Library/LaunchAgents", "/Contents/_CodeSignature"].map { sub -> String in
            var st = stat()
            guard lstat(bundle + sub, &st) == 0 else { return "-" }
            return "\(st.st_ino):\(st.st_mtimespec.tv_sec).\(st.st_mtimespec.tv_nsec):\(st.st_uid)"
        }.joined(separator: "|")
    }

    public static func isSealed(_ bundle: String) -> Bool {
        let key = cacheKey(bundle)
        lock.lock()
        if let c = cache[bundle], c.key == key, Date().timeIntervalSince(c.at) < 60 { lock.unlock(); return c.ok }
        lock.unlock()
        var code: SecStaticCode?
        var ok = false
        if SecStaticCodeCreateWithPath(URL(fileURLWithPath: bundle) as CFURL, [], &code) == errSecSuccess, let code {
            ok = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckNestedCode), nil) == errSecSuccess
        }
        lock.lock(); cache[bundle] = (key, Date(), ok); if cache.count > 16 { cache.removeAll() }; lock.unlock()
        return ok
    }
}

// MARK: - Lockdown false-alarm re-check (daemon start)

/// Decides whether a persisted, still-active lockdown is a false alarm that the daemon lifts by itself at start:
/// its trigger was RamPart's own (now verified) files, or it no longer qualifies under the current trigger policy.
/// A manual lockdown is never auto-lifted.
public enum EmergencyFalseAlarm {
    /// - Parameters:
    ///   - detection: the stored detection that started it (nil if gone).
    ///   - isVerifiedOwnFile: OwnInstallTrust.isVerifiedOwnFile.
    ///   - isOwnPath: path names one of RamPart's own install locations (verified or not), for files that were
    ///     quarantined and are now absent or reinstalled.
    /// - Returns: a plain-words reason to lift, or nil to keep the lockdown.
    public static func reason(state s: EmergencyState, detection: Detection?, isVerifiedOwnFile: (String) -> Bool,
                              isOwnPath: (String) -> Bool) -> String? {
        guard s.active, let r = s.reason, r.kind != .manual, s.automatic != false else { return nil }
        // Files the trigger named or that the lockdown quarantined.
        let quarantined = s.actions.filter { $0.kind == .quarantineFiles }.flatMap(\.paths)
        let files = Array(Set([r.path].compactMap { $0 } + quarantined))
        let ownFiles = files.filter(isOwnPath)
        if !files.isEmpty, ownFiles.count == files.count {
            // Every file involved is one of ours: a false alarm once they verify again (reinstalled or still there).
            let present = ownFiles.filter { FileManager.default.fileExists(atPath: $0) }
            if !present.isEmpty, present.allSatisfy(isVerifiedOwnFile) {
                return "It was started by \(Product.name)'s own files (\(present.map { ($0 as NSString).lastPathComponent }.sorted().joined(separator: ", "))), which verify as genuine."
            }
        }
        // Re-evaluate the trigger with today's policy.
        if let stored = detection {
            // The store keeps the calibrated (capped) score; the trigger saw the engine's raw score.
            let d = uncalibrated(stored)
            if EmergencyTriggerPolicy.evaluate(d) == nil {
                return "Its trigger (\(d.name)) no longer qualifies for a lockdown under the current rules."
            }
            let a = DetectionPolicy.assess(d)
            if !a.autoRemediate && !(d.category == .ransomware) {
                return "Its trigger (\(d.name)) is not certain enough for an automatic response under the current rules."
            }
        }
        // A single tamper or decoy signal never locks down any more (EmergencyNetworkPolicy); a lockdown with no
        // recorded second, independent signal no longer qualifies.
        if r.kind == .tampering || r.kind == .deception {
            let corroborated = (s.networkWhy ?? "").lowercased().contains("independent")
            if !corroborated { return "A single \(r.kind == .tampering ? "tamper" : "decoy") signal no longer starts a lockdown." }
            if let p = r.path, isOwnPath(p), isVerifiedOwnFile(p) {
                return "The \"tampering\" was with \(Product.name)'s own file, which verifies as genuine."
            }
        }
        return nil
    }

    /// The engine's score before calibration: combined evidence 100·(1 − Π(1 − s/100)), severity to match.
    public static func uncalibrated(_ d: Detection) -> Detection {
        var n = d
        let scores = d.evidence.filter { !DetectionPolicy.isContextOnly($0) }.map { Double(max(0, min(100, $0.score))) / 100 }
        let raw = scores.isEmpty ? d.confidence : Int((100 * (1 - scores.reduce(1) { $0 * (1 - $1) })).rounded())
        n.confidence = max(d.confidence, raw)
        let sev: Severity = n.confidence >= 90 ? .critical : n.confidence >= 75 ? .high : n.confidence >= 60 ? .medium : .low
        n.severity = max(d.severity, sev)
        return n
    }
}

// MARK: - Full Disk Access lost after an update

/// User incident 2026-11-09: every `rampart-setup.sh install-from` gives the ad-hoc signed service a new cdhash, and macOS
/// ties Full Disk Access to the exact code signature, so the switch the user turned on stops applying. Toggling it off
/// and on does not help: the old entry has to be removed and the service added again.
public enum ServiceFDAAdvice {
    public enum State: String, Sendable { case ok, missing, lostAfterUpdate }
    public static let noteID = "fda:lostAfterUpdate"
    public static let title = "The protection service lost Full Disk Access after an update"
    public static let why = "Each \(Product.name) update installs a new build of its service, and macOS ties Full Disk Access to the exact build. The switch you turned on earlier still shows, but it applies to the old build."

    /// `grantedCDHash`: the service's cdhash the last time it had Full Disk Access (nil = never had it).
    public static func state(hasAccess: Bool, grantedCDHash: String?, currentCDHash: String?) -> State {
        if hasAccess { return .ok }
        guard let g = grantedCDHash?.lowercased(), !g.isEmpty, let c = currentCDHash?.lowercased(), !c.isEmpty else { return .missing }
        return g == c ? .missing : .lostAfterUpdate
    }

    /// Exact steps: remove the stale entry, add the service again, switch it on.
    public static func steps(itemName: String = Product.daemonLabel,
                             binaryPath: String = "/Library/PrivilegedHelperTools/\(Product.daemonLabel)") -> [String] {
        ["Open System Settings › Privacy & Security › Full Disk Access.",
         "Select \(itemName) in the list and click the − (minus) button to remove it. Turning its switch off and on again is not enough.",
         "Click +, press Shift-Command-G, type \(binaryPath), press Return, then click Open.",
         "Make sure the switch next to the new \(itemName) is on. \(Product.name) notices within a few seconds; nothing needs restarting."]
    }

    public static func note(itemName: String = Product.daemonLabel, binaryPath: String = "/Library/PrivilegedHelperTools/\(Product.daemonLabel)",
                            at date: Date = Date()) -> HealthNote {
        let s = steps(itemName: itemName, binaryPath: binaryPath).enumerated().map { "\($0.offset + 1). \($0.element)" }.joined(separator: " ")
        return HealthNote(id: noteID, source: "fullDiskAccess", message: title, detail: why + " " + s,
                          fix: .fullDiskAccess, firstSeen: date, lastSeen: date)
    }
}
