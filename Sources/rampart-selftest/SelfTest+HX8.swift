import Foundation
import Darwin
import Security
import RampartShared

// hx8: the app's own attack surface (fake daemon socket, helper launch, notification actions, Dock/open
// injection, attacker text in UI, PasteGuard gating, single instance, UserDefaults secrets).
// The app target can't be imported here, so this suite (1) proves the OS primitives the app's peer check relies
// on behave as assumed, against a scratch socket owned by this process, and (2) pins the protections in the
// app sources so a later edit can't silently remove them.
extension SelfTest {
    static func hx8Checks() {
        hx8PeerPrimitives()
        hx8SourceInvariants()
        hx8SharedPolicies()
    }

    private static func hx8PeerPrimitives() {
        let dir = NSTemporaryDirectory() + "rampart-hx8-\(getpid())"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let path = dir + "/s.sock"
        func addr(_ p: String) -> sockaddr_un {
            var a = sockaddr_un(); a.sun_family = sa_family_t(AF_UNIX)
            withUnsafeMutableBytes(of: &a.sun_path) { raw in for (i, b) in Array(p.utf8).enumerated() { raw[i] = b } }
            return a
        }
        let srv = socket(AF_UNIX, SOCK_STREAM, 0)
        var sa = addr(path)
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bound = withUnsafePointer(to: &sa) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(srv, $0, len) } } == 0
        check(bound && listen(srv, 1) == 0, "hx8: scratch socket listens")
        defer { close(srv) }

        // lstat facts the socket-file policy uses.
        var st = stat()
        check(lstat(path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFSOCK && st.st_uid == getuid(), "hx8: lstat sees a user-owned socket")
        let link = dir + "/link.sock"
        symlink(path, link)
        var lst = stat()
        check(lstat(link, &lst) == 0 && (lst.st_mode & S_IFMT) == S_IFLNK, "hx8: a symlinked socket path is detectable with lstat")

        let cli = socket(AF_UNIX, SOCK_STREAM, 0)
        var ca = addr(path)
        let connected = withUnsafePointer(to: &ca) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(cli, $0, len) } } == 0
        check(connected, "hx8: client connects")
        defer { close(cli) }

        var uid: uid_t = 99, gid: gid_t = 0
        check(getpeereid(cli, &uid, &gid) == 0 && uid == getuid(), "hx8: getpeereid on the client side reports the server's uid")
        var pid: pid_t = 0
        var plen = socklen_t(MemoryLayout<pid_t>.size)
        check(getsockopt(cli, SOL_LOCAL, LOCAL_PEERPID, &pid, &plen) == 0 && pid == getpid(), "hx8: LOCAL_PEERPID names the serving process")

        var code: SecCode?
        let ok = SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary, [], &code) == errSecSuccess
        check(ok && code != nil, "hx8: SecCode for the peer pid is obtainable")
        // A requirement the peer can't meet (this test binary is not app.rampart.daemon signed by Apple) must fail.
        var req: SecRequirement?
        SecRequirementCreateWithString("identifier \"app.rampart.daemon\" and anchor apple" as CFString, [], &req)
        if let code, let req {
            check(SecCodeCheckValidity(code, [], req) != errSecSuccess, "hx8: a look-alike peer fails the helper requirement")
        } else { check(false, "hx8: requirement compiles") }
        // The peer's own designated requirement is satisfied by itself (the positive path the app relies on).
        var me: SecCode?, dr: SecRequirement?
        if SecCodeCopySelf([], &me) == errSecSuccess, let me,
           SecCodeCopyDesignatedRequirement(unsafeBitCast(me, to: SecStaticCode.self), [], &dr) == errSecSuccess, let dr, let code {
            check(SecCodeCheckValidity(code, [], dr) == errSecSuccess, "hx8: genuine peer satisfies its designated requirement")
        }
    }

    /// SafeText and DaemonPeerPolicy now live in RampartShared, so their pure policies are tested directly.
    static func hx8SharedPolicies() {
        check(SafeText.line("invoice\u{202E}fdp.exe") == "invoicefdp.exe", "hx8: SafeText strips bidi override")
        check(SafeText.line("a\nRamPart: safe") == "a RamPart: safe", "hx8: SafeText joins lines")
        check(SafeText.line(String(repeating: "x", count: 500), max: 10).count == 10, "hx8: SafeText caps length")
        check(SafeText.path("/" + String(repeating: "d/", count: 200) + "file.txt", max: 40).hasSuffix("file.txt"), "hx8: SafeText.path keeps the file name")
        let me = getuid()
        check(DaemonPeerPolicy.socketFileProblem(isSymlink: true, isSocket: true, ownerUID: me, rootSocket: false, myUID: me, parentOwnerUID: me, parentMode: 0o700) != nil, "hx8: symlinked socket refused")
        check(DaemonPeerPolicy.socketFileProblem(isSymlink: false, isSocket: true, ownerUID: 501 + 7, rootSocket: true, myUID: me, parentOwnerUID: 0, parentMode: 0o755) != nil, "hx8: non-root system socket refused")
        check(DaemonPeerPolicy.socketFileProblem(isSymlink: false, isSocket: true, ownerUID: me, rootSocket: false, myUID: me, parentOwnerUID: me, parentMode: 0o777) != nil, "hx8: world-writable socket folder refused")
        check(DaemonPeerPolicy.socketFileProblem(isSymlink: false, isSocket: true, ownerUID: me, rootSocket: false, myUID: me, parentOwnerUID: me, parentMode: 0o700) == nil, "hx8: private user socket accepted")
        check(DaemonPeerPolicy.peerProblem(peerUID: me &+ 1, myUID: me, rootSocket: false, signatureOK: { true }) != nil, "hx8: peer of another user refused")
        check(DaemonPeerPolicy.peerProblem(peerUID: me, myUID: me, rootSocket: true, signatureOK: { true }) != nil || me == 0, "hx8: non-root peer on system socket refused")
        check(DaemonPeerPolicy.peerProblem(peerUID: me, myUID: me, rootSocket: false, signatureOK: { false }) != nil || me == 0, "hx8: unsigned same-user peer refused")
    }

    private static func hx8SourceInvariants() {
        let app = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("RampartApp")
        func src(_ rel: String) -> String { (try? String(contentsOf: app.appendingPathComponent(rel), encoding: .utf8)) ?? "" }
        let client = src("DaemonClient.swift"), launcher = src("DaemonLauncher.swift"), model = src("AppModel.swift")
        let notifier = src("Notifier.swift"), main = src("RampartApp.swift"), paste = src("PasteGuardHost.swift")
        guard !client.isEmpty else { print("  (hx8: sources not found next to the build; source invariants skipped)"); return }

        check(client.contains("DaemonPeerTrust.peerProblem(fd: fd, path: path)"), "hx8: every connection is peer-checked before use")
        check(client.contains("DaemonPeerTrust.socketFileProblem(path: path)"), "hx8: socket file ownership/symlink check")
        check(client.contains("kSecCSCheckNestedCode"), "hx8: helper trust is anchored in the app's own sealed signature")
        check(client.contains("devOverridesAllowed, let i = CommandLine.arguments.firstIndex(of: \"--socket\")"), "hx8: --socket ignored by installed copies")
        if let r = client.range(of: "private func openSocket"), let w = client.range(of: "IPC.writeFrame", range: r.upperBound..<client.endIndex),
           let p = client.range(of: "peerProblem(fd:", range: r.upperBound..<client.endIndex) {
            check(p.lowerBound < w.lowerBound, "hx8: peer verified before the first byte is written")
        } else { check(false, "hx8: openSocket structure") }

        check(launcher.contains("fileSatisfiesHelperRequirement(helper.path)"), "hx8: helper signature verified before launch")
        check(launcher.contains("guard DaemonPeerTrust.devOverridesAllowed else { return nil }"), "hx8: --helper/--daemon-root gated")
        check(launcher.contains("O_NOFOLLOW"), "hx8: helper log opened without following symlinks")
        check(launcher.contains("hasPrefix(\"DYLD_\")"), "hx8: DYLD_* stripped from helper environment")

        let shared = (try? String(contentsOf: app.deletingLastPathComponent().appendingPathComponent("RampartShared/SafeText.swift"), encoding: .utf8)) ?? ""
        check(shared.contains("enum SafeText") && shared.contains("0x2028...0x202E") && model.contains("self.title = SafeText.line("),
              "hx8: activity text sanitised (bidi/control/newline/length)")
        check(notifier.contains("SafeText.line(d.path.map"), "hx8: threat notification name sanitised")
        check(notifier.contains("shouldHonourStayConnected"), "hx8: Stay connected action bound to a pending disconnect + token")
        check(notifier.contains("SafeText.line(networkName, max: 32)"), "hx8: Wi-Fi name sanitised in notification")
        check(main.contains("isGenuineSibling($0)"), "hx8: single instance requires a genuinely signed sibling")
        check(main.contains("RevealLimiter.shared.allow()"), "hx8: reveal notification rate-limited")
        check(main.contains("droppedScanPaths(urls)") && main.contains("maxDroppedPaths = 64"), "hx8: Dock/open paths validated and capped")
        check(paste.contains("RAMPART_NO_PRIVILEGED_TOOLS") && paste.contains("guard Self.allowed"), "hx8: PasteGuard gated")
        check(paste.contains("maxPending"), "hx8: PasteGuard event queue bounded")

        // No secrets in UserDefaults from the owned app files.
        let owned = ["DaemonClient.swift", "DaemonLauncher.swift", "AppModel.swift", "Notifier.swift", "PasteGuardHost.swift",
                     "PublicWiFiHost.swift", "RampartApp.swift", "PermissionGuidePanel.swift"]
        let secretish = try! NSRegularExpression(pattern: #"(UserDefaults[^\n]*|@AppStorage\([^\n]*)(password|secret|token|apikey|api_key|master|seed)"#, options: [.caseInsensitive])
        for f in owned {
            let s = src(f)
            check(secretish.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) == nil, "hx8: no secret-looking UserDefaults keys in \(f)")
        }
    }
}
