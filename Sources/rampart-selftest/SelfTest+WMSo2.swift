import Foundation
import Darwin
import CryptoKit
import RampartShared
import RampartRemediation
import RampartGuard

// wms-o2: restore/export, vault exhaustion, scan→quarantine swaps, sandbox profile gaps and Download Gate races.
// Inert fixtures under the scratchpad only. Under sandbox-exec this suite runs Apple's own /bin/ps, /bin/hostname,
// /usr/sbin/sysctl and /bin/sh -c "echo" to prove what the profile blocks; no quarantined content is executed.
extension SelfTest {
    static func wmsO2Checks() {
        let scratchBase = ProcessInfo.processInfo.environment["RAMPART_SCRATCH"]
            ?? "/private/tmp/claude-501/-Users-arankeyhan/ab330a0d-96bf-4eec-a6ed-51d815d3bfd2/scratchpad"
        let fm = FileManager.default
        let rawBase = URL(fileURLWithPath: scratchBase).appendingPathComponent("wmso2-\(UUID().uuidString.prefix(8))").path
        try? fm.createDirectory(atPath: rawBase, withIntermediateDirectories: true)
        let base: String = { guard let r = realpath(rawBase, nil) else { return rawBase }; defer { free(r) }; return String(cString: r) }()
        defer { try? fm.removeItem(atPath: base) }
        wmsO2Vault(base + "/v")
        wmsO2Sandbox(base + "/s")
        wmsO2Gate(base + "/g")
    }

    private static func o2Mode(_ p: String) -> mode_t { var st = stat(); return lstat(p, &st) == 0 ? st.st_mode & 0o7777 : 0 }
    private static func o2Write(_ p: String, _ s: String, mode: mode_t = 0o644) {
        FileManager.default.createFile(atPath: p, contents: Data(s.utf8)); chmod(p, mode)
    }
    private static func o2Sha(_ s: String) -> String { SHA256.hash(data: Data(s.utf8)).map { String(format: "%02x", $0) }.joined() }

    // MARK: Vault

    private static func wmsO2Vault(_ dir: String) {
        let fm = FileManager.default
        try? fm.createDirectory(atPath: dir + "/files", withIntermediateDirectories: true)
        guard let vault = try? QuarantineVault(root: URL(fileURLWithPath: dir + "/vault")) else { check(false, "o2: vault init"); return }

        // Scan → quarantine rename-swap: the hash the scanner saw is pinned.
        let f = dir + "/files/com.rampart.test.swap"
        o2Write(f, "com.rampart.test innocent replacement")
        let scannedHash = o2Sha("com.rampart.test what the scanner saw")
        var swapErr: Error?
        do { _ = try vault.quarantine(path: f, detectionName: "com.rampart.test.swap", expectedSHA256: scannedHash) } catch { swapErr = error }
        check(swapErr != nil && fm.fileExists(atPath: f), "o2: swapped file (hash differs from the scan) is not taken")
        check(vault.list().isEmpty, "o2: nothing stored after a refused swap")
        let realHash = sha256Hex(ofFileAt: f) ?? ""
        let okRec = try? vault.quarantine(path: f, detectionName: "com.rampart.test.swap", expectedSHA256: realHash.uppercased())
        check(okRec != nil && !fm.fileExists(atPath: f), "o2: matching hash is quarantined")

        // Exhaustion: per-item size cap, checked before the file is touched.
        let big = dir + "/files/com.rampart.test.big"
        o2Write(big, String(repeating: "A", count: 64 << 10), mode: 0o755)
        vault.maxItemBytes = 32 << 10
        var bigErr: Error?
        do { _ = try vault.quarantine(path: big, detectionName: "com.rampart.test.big") } catch { bigErr = error }
        check(bigErr != nil && fm.fileExists(atPath: big) && o2Mode(big) == 0o755, "o2: oversized item refused before any change")
        // Folder tree size cap.
        let bigDir = dir + "/files/com.rampart.test.bigdir"
        try? fm.createDirectory(atPath: bigDir + "/sub", withIntermediateDirectories: true)
        for i in 0..<3 { o2Write(bigDir + "/sub/f\(i)", String(repeating: "B", count: 16 << 10)) }
        var dirErr: Error?
        do { _ = try vault.quarantine(path: bigDir, detectionName: "com.rampart.test.bigdir") } catch { dirErr = error }
        check(dirErr != nil && fm.fileExists(atPath: bigDir + "/sub/f2"), "o2: oversized folder refused and put back")
        check(((try? fm.contentsOfDirectory(atPath: dir + "/vault/staging")) ?? []).allSatisfy {
            ((try? fm.contentsOfDirectory(atPath: dir + "/vault/staging/" + $0)) ?? []).isEmpty }, "o2: refused folder not left in staging")
        vault.maxItemBytes = 1 << 30
        // Item count and total-bytes quotas.
        vault.maxItemCount = 1
        let small = dir + "/files/com.rampart.test.small"
        o2Write(small, "com.rampart.test small")
        check((try? vault.quarantine(path: small, detectionName: "x")) == nil && fm.fileExists(atPath: small), "o2: item-count quota enforced")
        vault.maxItemCount = 20_000
        vault.maxVaultBytes = 1
        check((try? vault.quarantine(path: small, detectionName: "x")) == nil && fm.fileExists(atPath: small), "o2: vault-bytes quota enforced")
        vault.maxVaultBytes = 20 << 30
        vault.minFreeBytes = UInt64.max / 4
        check((try? vault.quarantine(path: small, detectionName: "x")) == nil && fm.fileExists(atPath: small), "o2: free-space floor enforced")
        vault.minFreeBytes = 2 << 30
        check(vault.usage().items == 1, "o2: usage counts stored items")

        // Bounded xattrs in the signed sidecar.
        let xf = dir + "/files/com.rampart.test.xattrs"
        o2Write(xf, "com.rampart.test xattrs")
        let val = [UInt8](repeating: 0x41, count: 64)
        for i in 0..<300 { _ = setxattr(xf, "com.rampart.test.x\(i)", val, val.count, 0, XATTR_NOFOLLOW) }
        if let r = try? vault.quarantine(path: xf, detectionName: "x"), let m = try? vault.metadata(id: r.id) {
            check(m.xattrs.count <= 256, "o2: xattrs kept with an item are capped")
        } else { check(false, "o2: xattr fixture quarantined") }

        // Restore: missing parents are created without following a link swapped into the path.
        let outside = dir + "/outside"
        try? fm.createDirectory(atPath: outside, withIntermediateDirectories: true)
        try? fm.createDirectory(atPath: dir + "/dest", withIntermediateDirectories: true)
        try? fm.createSymbolicLink(atPath: dir + "/dest/link", withDestinationPath: outside)
        if let id = okRec?.id {
            var e: Error?
            do { _ = try vault.restore(id: id, options: .init(alternatePath: dir + "/dest/link/new/sub/com.rampart.test.swap")) } catch { e = error }
            check(e != nil && !fm.fileExists(atPath: outside + "/new"), "o2: restore never creates folders through a swapped link")
            let good = dir + "/dest/a/b/com.rampart.test.swap"
            let out = try? vault.restore(id: id, options: .init(alternatePath: good))
            check(out == good && fm.fileExists(atPath: good), "o2: restore creates missing real folders")
        } else { check(false, "o2: restore fixture") }
        check((try? SafeFS.makeParents(dir + "/dest/link/x", owner: nil, isProtected: { _ in false })) == nil
              && !fm.fileExists(atPath: outside + "/x"), "o2: makeParents refuses a link ancestor")
        check((try? SafeFS.makeParents(dir + "/dest/p/q", owner: nil, isProtected: { $0.hasSuffix("/p") })) == nil
              && !fm.fileExists(atPath: dir + "/dest/p"), "o2: makeParents refuses a protected folder")
    }

    // MARK: Sandbox profile

    private static func wmsO2Sandbox(_ dir: String) {
        let fm = FileManager.default
        try? fm.createDirectory(atPath: dir + "/w", withIntermediateDirectories: true)
        let w = dir + "/w"
        let tools = ["/bin/ps", "/bin/hostname", "/usr/sbin/sysctl", "/bin/sh"]
        guard let p = SandboxProfile.generate(workDir: w, allowedExec: tools, home: NSHomeDirectory()) else {
            check(false, "o2: profile generated"); return
        }
        check(!p.contains("(allow sysctl-read)\n") && p.contains("(allow sysctl-read (sysctl-name-prefix \"hw.\")"), "o2: sysctl reads are an allow-list")
        check(!p.contains("\"kern.proc") && !p.contains("kern.hostname"), "o2: process list and host name not readable")
        check(!p.contains("(allow network") && !p.contains("(allow mach") && !p.contains("(allow iokit") && !p.contains("(allow appleevent")
              && !p.contains("(allow process-fork") && !p.contains("(allow signal)") && !p.contains("(allow ipc"), "o2: no network/mach/IOKit/AppleEvents/fork/IPC allows")
        guard fm.isExecutableFile(atPath: "/usr/bin/sandbox-exec") else { return }
        let pf = dir + "/p.sb"
        try? Data(p.utf8).write(to: URL(fileURLWithPath: pf))
        let ps = o2Run("/usr/bin/sandbox-exec", ["-f", pf, "/bin/ps", "-A", "-o", "pid="], cwd: w)
        let pids = ps.out.split(separator: "\n").filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
        check(pids.count <= 1, "o2: sandboxed item can't list other processes (got \(pids.count))")
        let hn = o2Run("/usr/bin/sandbox-exec", ["-f", pf, "/bin/hostname"], cwd: w)
        check(hn.out.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, "o2: sandboxed item can't read the host name")
        let ost = o2Run("/usr/bin/sandbox-exec", ["-f", pf, "/usr/sbin/sysctl", "-n", "kern.ostype"], cwd: w)
        check(ost.out.contains("Darwin"), "o2: allowed sysctls still work (libSystem needs them)")
        let sh = o2Run("/usr/bin/sandbox-exec", ["-f", pf, "/bin/sh", "-c", "echo o2-ok"], cwd: w)
        check(sh.out.contains("o2-ok"), "o2: shell still runs under the tighter profile")
        let home = o2Run("/usr/bin/sandbox-exec", ["-f", pf, "/bin/sh", "-c", "set -- \"$0\"/*; [ -e \"$1\" ] && echo LEAK; echo x > /private/tmp/com.rampart.test.o2 && echo LEAK", NSHomeDirectory()], cwd: w)
        check(!home.out.contains("LEAK") && !fm.fileExists(atPath: "/private/tmp/com.rampart.test.o2"), "o2: no home listing, no writes outside the work folder")
    }

    private static func o2Run(_ tool: String, _ args: [String], cwd: String) -> (code: Int32, out: String) {
        let p = Process(); p.executableURL = URL(fileURLWithPath: tool); p.arguments = args
        p.currentDirectoryURL = URL(fileURLWithPath: cwd)
        let o = Pipe(); p.standardOutput = o; p.standardError = FileHandle.nullDevice; p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { return (-1, "") }
        let d = o.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: d, as: UTF8.self))
    }

    // MARK: Download Gate

    private static func wmsO2Gate(_ dir: String) {
        let fm = FileManager.default
        let home = dir + "/home", dl = home + "/Downloads", state = dir + "/state", outside = dir + "/outside"
        for d in [dl, state, outside + "/MacOS"] { try? fm.createDirectory(atPath: d, withIntermediateDirectories: true) }
        let gate = DownloadGateService(directory: URL(fileURLWithPath: state), home: home,
                                       signer: FakeGateSigner(trusted: ["linked-signed", "Twisted.app", "Signed2.app"]), roots: [(dl, "Downloads")])
        var decisions = 0
        gate.onDecision = { _ in decisions += 1 }
        gate.trash = { try FileManager.default.removeItem(at: $0) }
        gate.stableSeconds = 0
        func macho(_ p: String, _ mode: mode_t = 0o755) {
            var b: [UInt8] = [0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0, 0, 1]; b += [UInt8](repeating: 0, count: 120)
            fm.createFile(atPath: p, contents: Data(b)); chmod(p, mode)
        }
        func renote(_ p: String) -> Bool { let n = decisions; gate.noteChanged(p); gate.tick(now: Date().addingTimeInterval(5)); return decisions > n }

        // Execute bits put back after the check (chmod restore) are noticed and removed again.
        macho(dl + "/tool")
        let held = gate.process(dl + "/tool")
        check(held?.verdict == .held && o2Mode(dl + "/tool") & 0o111 == 0, "o2: unsigned tool held")
        chmod(dl + "/tool", 0o755)
        check(renote(dl + "/tool") && o2Mode(dl + "/tool") & 0o111 == 0, "o2: chmod +x after the check re-gates the file")
        chmod(dl + "/tool", 0o755)
        check(gate.reverify() >= 1 && o2Mode(dl + "/tool") & 0o111 == 0, "o2: periodic re-check strips a restored execute bit")
        // Quarantine flag stripped after the check.
        _ = removexattr(dl + "/tool", "com.apple.quarantine", XATTR_NOFOLLOW)
        check(renote(dl + "/tool") && DownloadGateService.hasQuarantineFlag(dl + "/tool"), "o2: removed quarantine flag is noticed and re-added")
        _ = removexattr(dl + "/tool", "com.apple.quarantine", XATTR_NOFOLLOW)
        gate.reverify()
        check(DownloadGateService.hasQuarantineFlag(dl + "/tool"), "o2: periodic re-check re-adds the quarantine flag")
        // Executed through another hard link: the bits live on the inode, and a chmod through the other name is caught.
        _ = link(dl + "/tool", outside + "/other-name")
        chmod(outside + "/other-name", 0o755)
        gate.reverify()
        check(o2Mode(outside + "/other-name") & 0o111 == 0, "o2: chmod through another hard link is undone")
        unlink(outside + "/other-name")

        // Allow: same inode only, and never setuid/setgid.
        macho(dl + "/suid", 0o4755)
        if let it = gate.process(dl + "/suid") {
            _ = try? gate.decide(id: it.id, allow: true)
            check(o2Mode(dl + "/suid") == 0o755, "o2: allow never restores setuid/setgid")
        } else { check(false, "o2: setuid fixture gated") }
        macho(dl + "/swapme")
        if let it = gate.process(dl + "/swapme") {
            unlink(dl + "/swapme"); o2Write(dl + "/swapme", "#!/bin/sh\necho com.rampart.test\n", mode: 0o644)
            _ = try? gate.decide(id: it.id, allow: true)
            check(o2Mode(dl + "/swapme") & 0o111 == 0, "o2: allow doesn't make a swapped-in file executable")
        } else { check(false, "o2: swap fixture gated") }

        // A signed program that also has another name elsewhere is held.
        macho(dl + "/linked-signed")
        _ = link(dl + "/linked-signed", outside + "/second")
        let ls = gate.process(dl + "/linked-signed")
        check(ls?.verdict == .held && o2Mode(dl + "/linked-signed") & 0o111 == 0, "o2: hard-linked program held even when signed")
        unlink(outside + "/second")

        // App bundles: payload outside Contents/MacOS is stripped; Info.plist pointing outside MacOS holds a signed app.
        let app = dl + "/Twisted.app"
        for d in ["/Contents/MacOS", "/Contents/Resources"] { try? fm.createDirectory(atPath: app + d, withIntermediateDirectories: true) }
        macho(app + "/Contents/MacOS/Twisted"); macho(app + "/Contents/Resources/payload")
        let plist: [String: Any] = ["CFBundleExecutable": "../Resources/payload"]
        try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0).write(to: URL(fileURLWithPath: app + "/Contents/Info.plist"))
        let tw = gate.process(app)
        check(tw?.verdict == .held, "o2: Info.plist executable outside MacOS holds the app")
        check(o2Mode(app + "/Contents/Resources/payload") & 0o111 == 0 && tw?.strippedModes[app + "/Contents/Resources/payload"] != nil,
              "o2: executable payload in Resources stripped")
        // Info.plist rewritten after the check with its mtime put back: still re-gated (ctime can't be reset).
        let app2 = dl + "/Signed2.app"
        try? fm.createDirectory(atPath: app2 + "/Contents/MacOS", withIntermediateDirectories: true)
        macho(app2 + "/Contents/MacOS/Signed2")
        try? PropertyListSerialization.data(fromPropertyList: ["CFBundleExecutable": "Signed2"], format: .xml, options: 0)
            .write(to: URL(fileURLWithPath: app2 + "/Contents/Info.plist"))
        let s2 = gate.process(app2)
        check(s2?.verdict == .cleared && o2Mode(app2 + "/Contents/MacOS/Signed2") == 0o755, "o2: clean signed app cleared")
        var st = stat(); lstat(app2 + "/Contents/Info.plist", &st)
        let oldTimes = [timeval(tv_sec: st.st_atimespec.tv_sec, tv_usec: 0), timeval(tv_sec: st.st_mtimespec.tv_sec, tv_usec: Int32(st.st_mtimespec.tv_nsec / 1000))]
        usleep(20_000)
        try? PropertyListSerialization.data(fromPropertyList: ["CFBundleExecutable": "Evil__2"], format: .xml, options: 0)
            .write(to: URL(fileURLWithPath: app2 + "/Contents/Info.plist"), options: [])
        _ = oldTimes.withUnsafeBufferPointer { utimes(app2 + "/Contents/Info.plist", $0.baseAddress) }
        check(renote(app2 + "/Contents/Info.plist"), "o2: Info.plist edited after the check (mtime forged) re-gates the app")

        // Symlink swaps: a linked folder inside a bundle or the Downloads path never redirects a chmod.
        macho(outside + "/MacOS/main")
        let trap = dl + "/Trap.app"
        try? fm.createDirectory(atPath: trap, withIntermediateDirectories: true)
        try? fm.createSymbolicLink(atPath: trap + "/Contents", withDestinationPath: outside)
        _ = gate.process(trap)
        check(o2Mode(outside + "/MacOS/main") == 0o755, "o2: link inside a bundle never redirects the chmod")
        try? fm.createSymbolicLink(atPath: dl + "/sub", withDestinationPath: outside + "/MacOS")
        let viaLink = gate.process(dl + "/sub/main")
        check(viaLink == nil && o2Mode(outside + "/MacOS/main") == 0o755, "o2: path through a linked folder is not gated or changed")
    }
}
