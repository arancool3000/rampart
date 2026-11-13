import Foundation
import CryptoKit
import Darwin
import RampartShared
import RampartRemediation

// Quarantine manager back end: restore to another place, encrypted export, and a best-effort
// "Run in sandbox" using /usr/bin/sandbox-exec. sandbox-exec is deprecated by Apple and is
// containment, not a VM. The profile generator and log parser are pure so the self-test can check them.

// MARK: - Daemon actions

enum QuarantineSandbox {
    private static let runLock = NSLock()
    private static let password = "infected"

    private static func vault(_ p: Protection) throws -> QuarantineVault {
        guard let v = (p.services.quarantine as? VaultQuarantine)?.vault else {
            throw ServiceError.unavailable("the encrypted quarantine vault")
        }
        return v
    }

    private static func home(of uid: uid_t) -> String? { getpwuid(uid).map { String(cString: $0.pointee.pw_dir) } }

    /// Destination checks for restore-to and export: absolute, not existing, parent is a real folder the peer owns
    /// (or an admin peer when root), under the peer's home, /Users/Shared or /Applications.
    static func checkDestination(_ path: String, peer: Peer) throws -> String {
        let std = (path as NSString).standardizingPath
        guard std.hasPrefix("/"), !std.contains("\0") else { throw ServiceError.failed("destination must be an absolute path") }
        var st = stat()
        if lstat(std, &st) == 0 { throw ServiceError.failed("\(std) already exists") }
        let parent = (std as NSString).deletingLastPathComponent
        guard let real = realpath(parent, nil) else { throw ServiceError.failed("folder \(parent) doesn't exist") }
        let rp = String(cString: real); free(real)
        guard lstat(rp, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR else { throw ServiceError.failed("\(parent) isn't a folder") }
        let h = home(of: peer.uid) ?? "/nonexistent"
        let roots = [h, "/Users/Shared", "/Applications"]
        guard roots.contains(where: { rp == $0 || rp.hasPrefix($0 + "/") }) else {
            throw ServiceError.denied("choose a place in your home folder, /Users/Shared or /Applications")
        }
        if getuid() == 0, st.st_uid != peer.uid, !(peer.isAdmin && rp.hasPrefix("/Applications")) {
            throw ServiceError.denied("you don't own \(rp)")
        }
        return (rp as NSString).appendingPathComponent((std as NSString).lastPathComponent)
    }

    static func restore(_ p: Protection, id: UUID, to path: String, allow: Bool, peer: Peer) throws -> String {
        let v = try vault(p)
        let rec = try v.metadata(id: id).record
        try checkItemAccess(rec, peer: peer)
        let dest = try checkDestination(path, peer: peer)
        // hx3: the copy is created owned by the peer (never briefly root-owned), setuid/setgid bits are dropped, and the
        // destination folder's owner is re-checked on the pinned descriptor inside the vault.
        let gid = getpwuid(peer.uid)?.pointee.pw_gid ?? 20
        let asRoot = getuid() == 0
        let adminApps = peer.isAdmin && dest.hasPrefix("/Applications/")
        // wms-o2: the macOS quarantine flag comes back too, so Gatekeeper still checks the restored copy on first open.
        let opts = QuarantineVault.RestoreOptions(alternatePath: dest, reapplyQuarantineXattr: true, allowlist: false,
                                                  ownerUID: asRoot ? peer.uid : nil, ownerGID: asRoot ? gid : nil,
                                                  requireParentOwnerUID: asRoot && !adminApps ? peer.uid : nil)
        let out = try v.restore(id: id, options: opts)
        if !rec.sha256.isEmpty {
            p.state.update { s in var r = s.restored ?? [:]; if r.count > 500 { r.removeAll() }; r[out] = rec.sha256; s.restored = r }
            if allow { p.allow(sha256: rec.sha256) }
        }
        logInfo("restored \(id.uuidString) to \(out) (chosen location)\(allow ? " (trusted)" : "")")
        p.activity.add(.restore, "Restored \(rec.detectionName)", detail: out, outcome: allow ? "restored elsewhere and trusted" : "restored elsewhere",
                       event: .restored, actor: .user, target: out, sha256: rec.sha256, refID: id.uuidString, facts: ["threat": rec.detectionName])
        return out
    }

    /// A non-admin may only restore or export items that were theirs (hx3: otherwise the root daemon could hand one
    /// user another user's quarantined file). Admins can already read everything.
    static func checkItemAccess(_ rec: QuarantineRecord, peer: Peer) throws {
        if peer.uid == 0 || peer.isAdmin || rec.ownerUID == peer.uid { return }
        throw ServiceError.denied("this item belonged to another user; ask an administrator")
    }

    /// Plaintext of a quarantined item (verified metadata, GCM tag and SHA-256). Kept in memory only.
    /// hx3: decryption stays inside the vault; this file never reads or derives the vault key.
    static func plaintext(_ v: QuarantineVault, id: UUID) throws -> (VaultItemMetadata, Data) {
        do { return try v.verifiedPlaintext(id: id) }
        catch let e as RemediationError { throw ServiceError.failed("\(e)") }
    }

    /// Private 0700 temp folder (never the item's original path).
    static func makePrivateDir() throws -> String {
        let base = (NSTemporaryDirectory() as NSString).resolvingSymlinksInPath
        let dir = (base as NSString).appendingPathComponent("rampart-q-\(UUID().uuidString)")
        guard mkdir(dir, 0o700) == 0 else { throw ServiceError.failed("cannot create private folder") }
        chmod(dir, 0o700)
        guard let r = realpath(dir, nil) else { throw ServiceError.failed("cannot resolve private folder") }
        defer { free(r) }
        return String(cString: r)
    }

    static func removeTree(_ dir: String) {
        guard dir.contains("/rampart-q-") else { return }
        if (try? FileManager.default.removeItem(atPath: dir)) == nil {
            // -P: never follow a symlink the item left behind. Clear user flags too (file-write-flags is denied in the
            // profile, but be defensive), then retry.
            _ = run("/usr/bin/chflags", ["-R", "-P", "nouchg,nouappnd", dir], timeout: 10)
            _ = run("/bin/chmod", ["-R", "-P", "u+rwx", dir], timeout: 10)
            try? FileManager.default.removeItem(atPath: dir)
        }
    }

    private static func writeNew(_ data: Data, to path: String, mode: mode_t) throws {
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode)
        guard fd >= 0 else { throw ServiceError.failed("create \(path): \(String(cString: strerror(errno)))") }
        defer { close(fd) }
        let ok = data.withUnsafeBytes { data.isEmpty || write(fd, $0.baseAddress, data.count) == data.count }
        guard ok else { throw ServiceError.failed("write \(path)") }
        fchmod(fd, mode)
    }

    /// Writes the item into `dir`; returns the path of the extracted file or bundle.
    static func extract(_ meta: VaultItemMetadata, _ plain: Data, into dir: String, scratch: String) throws -> String {
        let name = SandboxProfile.safeName(meta.record.originalPath)
        if meta.isDirectory {
            let zip = (scratch as NSString).appendingPathComponent("item.zip")
            try writeNew(plain, to: zip, mode: 0o600)
            let unpack = (scratch as NSString).appendingPathComponent("unpack")
            guard mkdir(unpack, 0o700) == 0 else { throw ServiceError.failed("cannot create unpack folder") }
            let r = run("/usr/bin/ditto", ["-x", "-k", zip, unpack], timeout: 60)
            guard r.status == 0 else { throw ServiceError.failed("could not unpack the folder") }
            let inner = (unpack as NSString).appendingPathComponent((meta.record.originalPath as NSString).lastPathComponent)
            let dest = (dir as NSString).appendingPathComponent(name)
            guard rename(inner, dest) == 0 else { throw ServiceError.failed("could not place the unpacked folder") }
            return dest
        }
        let dest = (dir as NSString).appendingPathComponent(name)
        try writeNew(plain, to: dest, mode: 0o600)
        return dest
    }

    // MARK: Export

    /// Zip encrypted with the conventional sample password "infected", so it can't be opened or run by accident.
    static func export(_ p: Protection, id: UUID, to path: String, peer: Peer) throws -> (path: String, password: String) {
        let v = try vault(p)
        try checkItemAccess(try v.metadata(id: id).record, peer: peer)
        let dest = try checkDestination(path, peer: peer)
        let (meta, plain) = try plaintext(v, id: id)
        let tmp = try makePrivateDir(); defer { removeTree(tmp) }
        let stage = (tmp as NSString).appendingPathComponent("stage"); mkdir(stage, 0o700)
        let item = try extract(meta, plain, into: stage, scratch: tmp)
        let zip = (tmp as NSString).appendingPathComponent("export.zip")
        let r = run("/usr/bin/zip", ["-q", "-r", "-y", "-P", password, zip, (item as NSString).lastPathComponent], cwd: stage, timeout: 120)
        guard r.status == 0, let z = FileManager.default.contents(atPath: zip) else { throw ServiceError.failed("could not create the encrypted zip") }
        // hx3: pin the destination folder (no symlink swapped in after checkDestination), re-check its owner on the
        // descriptor, and create the zip already owned by the peer.
        let pinned: SafeFS.PinnedDir
        do { pinned = try SafeFS.pin((dest as NSString).deletingLastPathComponent) } catch { throw ServiceError.denied("\(error)") }
        if getuid() == 0, !(peer.isAdmin && dest.hasPrefix("/Applications/")) {
            guard let st = pinned.stat(), st.st_uid == peer.uid else { throw ServiceError.denied("you don't own \(pinned.realPath)") }
        }
        do {
            try SafeFS.createFile(in: pinned, name: (dest as NSString).lastPathComponent, data: z, mode: 0o600,
                                  owner: (peer.uid, getpwuid(peer.uid)?.pointee.pw_gid ?? 20))
        } catch { throw ServiceError.failed("could not save the zip: \(error)") }
        p.activity.add(.quarantine, "Exported encrypted copy of \(meta.record.detectionName)", detail: dest, outcome: "exported",
                       event: .exported, actor: .user, target: dest, sha256: meta.record.sha256, facts: ["threat": meta.record.detectionName])
        return (dest, password)
    }

    // MARK: Sandbox run

    static func run(_ p: Protection, id: UUID, confirmation: String, peer: Peer) throws -> SandboxReport {
        if ProcessInfo.processInfo.environment["RAMPART_NO_PRIVILEGED_TOOLS"] == "1" {
            throw ServiceError.denied("sandbox runs are disabled (RAMPART_NO_PRIVILEGED_TOOLS=1)")
        }
        guard getuid() != 0 else {
            throw ServiceError.denied("the system service never runs quarantined code as root; use the user-session helper")
        }
        guard peer.uid == getuid() else { throw ServiceError.denied("only the session owner can run items in the sandbox") }
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/sandbox-exec") else {
            throw ServiceError.unavailable("/usr/bin/sandbox-exec")
        }
        let v = try vault(p)
        let rec = try v.metadata(id: id).record
        let conf = p.store.all().filter { $0.sha256 == rec.sha256 && !rec.sha256.isEmpty }.map(\.confidence).max()
        guard SandboxProfile.confirmationOK(confirmation, confidence: conf) else {
            throw ServiceError.denied("type RUN to confirm running this high-confidence detection")
        }
        guard runLock.try() else { throw ServiceError.failed("another sandbox run is in progress") }
        defer { runLock.unlock() }

        let (meta, plain) = try plaintext(v, id: id)
        let base = try makePrivateDir(); defer { removeTree(base) }
        let work = (base as NSString).appendingPathComponent("work")
        let out = (base as NSString).appendingPathComponent("out")
        guard mkdir(work, 0o700) == 0, mkdir(out, 0o700) == 0 else { throw ServiceError.failed("cannot create sandbox folders") }
        let item = try extract(meta, plain, into: work, scratch: out)
        var notes: [String] = []

        // What to execute.
        var exe = item
        var interp: String?
        if meta.isDirectory {
            guard item.hasSuffix(".app"),
                  let info = NSDictionary(contentsOfFile: (item as NSString).appendingPathComponent("Contents/Info.plist")),
                  let name = info["CFBundleExecutable"] as? String, !name.contains("/") else {
                throw ServiceError.failed("only app bundles, programs and scripts can be run in the sandbox")
            }
            exe = (item as NSString).appendingPathComponent("Contents/MacOS/\(name)")
            notes.append("App bundle: ran its main executable \(name).")
        } else {
            let head = plain.prefix(256)
            let magic = head.prefix(4).map { $0 }
            let machO: Set<[UInt8]> = [[0xcf, 0xfa, 0xed, 0xfe], [0xce, 0xfa, 0xed, 0xfe], [0xca, 0xfe, 0xba, 0xbe], [0xfe, 0xed, 0xfa, 0xcf], [0xbe, 0xba, 0xfe, 0xca]]
            if !machO.contains(magic) {
                let first = String(decoding: head, as: UTF8.self).components(separatedBy: "\n").first ?? ""
                let wanted = SandboxProfile.interpreter(forExtension: (item as NSString).pathExtension) ?? SandboxProfile.interpreter(forShebang: first)
                guard let wanted else { throw ServiceError.failed("this item isn't a program or a script \(Product.name) knows how to run") }
                // hx3: run the real interpreter, never the /usr/bin/python3 shim (it can start xcrun or an install prompt).
                guard let real = SandboxProfile.resolvedInterpreter(wanted) else {
                    throw ServiceError.unavailable("\(wanted) (install the Command Line Tools to run Python scripts)")
                }
                interp = real
                notes.append("Script: ran with \(real) inside the same profile. Scripts can't start other programs, so many stop early.")
            }
        }
        // hx3: links in the item that lead outside the sandbox folder (or nowhere) are removed before anything runs.
        let removed = SandboxProfile.removeEscapingLinks(under: work)
        if !removed.isEmpty { notes.append("Removed \(removed.count) link(s) in the item that pointed outside the sandbox folder.") }
        guard let rexe = realpath(exe, nil) else { throw ServiceError.failed("executable not found in the item") }
        let realExe = String(cString: rexe); free(rexe)
        guard realExe.hasPrefix(work + "/") else { throw ServiceError.denied("the item's executable points outside the sandbox folder") }
        chmod(realExe, interp == nil ? 0o700 : 0o600)

        let home = Self.home(of: getuid()) ?? NSHomeDirectory()
        let execs = interp.map { [$0, realExe] } ?? [realExe]
        let interpArgs = interp.map { SandboxProfile.interpreterArguments($0) } ?? []
        guard let profile = SandboxProfile.generate(workDir: work, allowedExec: execs, home: home) else {
            throw ServiceError.failed("could not build the sandbox profile")
        }
        let profilePath = (out as NSString).appendingPathComponent("profile.sb")
        try writeNew(Data(profile.utf8), to: profilePath, mode: 0o600)
        let argv = ["/usr/bin/sandbox-exec", "-f", profilePath] + (interp.map { [$0] + interpArgs + [realExe] } ?? [realExe])
        let stdoutPath = (out as NSString).appendingPathComponent("stdout"), stderrPath = (out as NSString).appendingPathComponent("stderr")
        let env = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=\(work)", "TMPDIR=\(work)/", "LANG=en_US.UTF-8"]

        let started = Date()
        let pid = try spawn(argv, env: env, cwd: work, stdout: stdoutPath, stderr: stderrPath)
        p.activity.add(.quarantine, "Sandbox run of \(rec.detectionName)", detail: (rec.originalPath as NSString).lastPathComponent, outcome: "started",
                       event: .sandboxRun, actor: .user, sha256: rec.sha256, facts: ["threat": rec.detectionName])
        var seen: Set<Int32> = [pid]
        var status: Int32 = 0
        var exited = false
        var overDisk = false
        var tick = 0
        while Date().timeIntervalSince(started) < SandboxProfile.timeLimit {
            for c in descendants(of: pid) { seen.insert(c) }
            if waitpid(pid, &status, WNOHANG) == pid { exited = true; break }
            // hx3: stop an item that tries to fill the disk (work folder + captured output), checked every second.
            tick += 1
            if tick % 10 == 0, SandboxProfile.diskUsageExceeded([work, stdoutPath, stderrPath]) { overDisk = true; break }
            usleep(100_000)
        }
        let timedOut = !exited && !overDisk
        // Kill the process tree (group + every descendant we saw), then reap.
        for c in descendants(of: pid) { seen.insert(c) }
        kill(-pid, SIGKILL)
        for c in seen where c != pid { if descendantOrGroup(c, pid) { kill(c, SIGKILL) } }
        if !exited { kill(pid, SIGKILL); _ = waitpid(pid, &status, 0) }
        let seconds = Date().timeIntervalSince(started)
        let killed = seen.count - (exited ? 1 : 0)

        let (so, t1) = readCapped(stdoutPath), (se, t2) = readCapped(stderrPath)
        // Sandbox violations from the unified log, scoped to our pids (read-only).
        usleep(1_200_000)
        let fmt = DateFormatter(); fmt.locale = Locale(identifier: "en_US_POSIX"); fmt.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let pidTerms = seen.sorted().prefix(64).map { "eventMessage CONTAINS \"(\($0))\"" }.joined(separator: " OR ")
        let lr = run("/usr/bin/log", ["show", "--style", "ndjson", "--start", fmt.string(from: started.addingTimeInterval(-1)),
                                      "--predicate", "sender == \"Sandbox\" AND (\(pidTerms))"], timeout: 30, maxBytes: 8 << 20)
        var messages: [String] = []
        for line in lr.out.split(separator: "\n") {
            if let d = line.data(using: .utf8), let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
               let m = o["eventMessage"] as? String { messages.append(m) }
        }
        if lr.status != 0 { notes.append("Couldn't read the sandbox log; the list of touched files may be incomplete.") }
        let violations = SandboxProfile.parseViolations(messages, pids: seen)
        if overDisk { notes.append("Stopped early: it wrote more than \(SandboxProfile.diskLimitBytes >> 20) MB or too many files.") }
        else if timedOut { notes.append("Stopped after \(Int(SandboxProfile.timeLimit)) seconds.") }
        notes.append("The temporary folder was deleted after the run.")

        let display = ["sandbox-exec", "-f", "profile.sb"] + (interp.map { [$0] + interpArgs } ?? []) + [SandboxProfile.sanitizeOutput((item as NSString).lastPathComponent)]
        let exitCode: Int32? = exited ? ((status & 0x7f) == 0 ? (status >> 8) & 0xff : -(status & 0x7f)) : nil
        p.activity.add(.quarantine, "Sandbox run finished: \(rec.detectionName)",
                       detail: "\(violations.count) blocked action(s)", outcome: overDisk ? "disk limit" : timedOut ? "time limit" : "exited",
                       event: .sandboxRun, actor: .user, reason: "\(violations.count) action(s) were blocked by the sandbox.",
                       sha256: rec.sha256, facts: ["threat": rec.detectionName])
        return SandboxReport(itemName: SandboxProfile.sanitizeOutput((rec.originalPath as NSString).lastPathComponent), sha256: rec.sha256, command: display,
                             startedAt: started, seconds: seconds, exitStatus: exitCode, timedOut: timedOut,
                             killedProcesses: max(0, killed), stdout: so, stderr: se, outputTruncated: t1 || t2,
                             violations: violations, touchedPaths: SandboxProfile.touchedPaths(violations), notes: notes,
                             profile: profile)
    }

    private static func descendants(of pid: Int32) -> [Int32] {
        var out: [Int32] = []; var queue = [pid]; var guardN = 0
        while let p = queue.popLast(), guardN < 4096 {
            guardN += 1
            var buf = [pid_t](repeating: 0, count: 256)
            let n = buf.withUnsafeMutableBytes { proc_listchildpids(p, $0.baseAddress, Int32($0.count)) }
            guard n > 0 else { continue }
            for c in buf.prefix(min(Int(n), buf.count)) where c > 0 && !out.contains(c) { out.append(c); queue.append(c) }
        }
        return out
    }

    /// Guards against pid reuse: only kill pids still in our tree or our process group.
    private static func descendantOrGroup(_ c: Int32, _ root: Int32) -> Bool {
        getpgid(c) == root || descendants(of: root).contains(c)
    }

    private static func readCapped(_ path: String, cap: Int = 64 << 10) -> (String, Bool) {
        guard let fh = FileHandle(forReadingAtPath: path) else { return ("", false) }
        defer { try? fh.close() }
        let d = (try? fh.read(upToCount: cap + 1)) ?? Data()
        return (SandboxProfile.sanitizeOutput(String(decoding: d.prefix(cap), as: UTF8.self)), d.count > cap)
    }

    /// posix_spawn in a new process group, stdin from /dev/null, output to files, all other fds closed.
    private static func spawn(_ argv: [String], env: [String], cwd: String, stdout: String, stderr: String) throws -> Int32 {
        var fa: posix_spawn_file_actions_t? = nil
        var attr: posix_spawnattr_t? = nil
        posix_spawn_file_actions_init(&fa); posix_spawnattr_init(&attr)
        defer { posix_spawn_file_actions_destroy(&fa); posix_spawnattr_destroy(&attr) }
        posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0)
        posix_spawn_file_actions_addopen(&fa, 1, stdout, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        posix_spawn_file_actions_addopen(&fa, 2, stderr, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        posix_spawn_file_actions_addchdir_np(&fa, cwd)
        posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF))
        posix_spawnattr_setpgroup(&attr, 0)
        var all = sigset_t(); sigfillset(&all); posix_spawnattr_setsigdefault(&attr, &all)
        var cargs = argv.map { strdup($0) } + [nil]
        var cenv = env.map { strdup($0) } + [nil]
        defer { cargs.forEach { free($0) }; cenv.forEach { free($0) } }
        var pid: pid_t = 0
        let rc = posix_spawn(&pid, argv[0], &fa, &attr, &cargs, &cenv)
        guard rc == 0 else { throw ServiceError.failed("could not start sandbox-exec: \(String(cString: strerror(rc)))") }
        return pid
    }

    /// Small runner for Apple tools (ditto, zip, log, chmod) with a time limit and output cap.
    @discardableResult
    static func run(_ tool: String, _ args: [String], cwd: String? = nil, timeout: TimeInterval, maxBytes: Int = 1 << 20) -> (status: Int32, out: String) {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: tool); proc.arguments = args
        if let cwd { proc.currentDirectoryURL = URL(fileURLWithPath: cwd) }
        let pipe = Pipe(); proc.standardOutput = pipe; proc.standardError = FileHandle.nullDevice
        proc.standardInput = FileHandle.nullDevice
        do { try proc.run() } catch { return (-1, "") }
        let lock = NSLock(); var data = Data()
        let reader = Thread {
            let h = pipe.fileHandleForReading
            while true {
                let chunk = h.availableData
                if chunk.isEmpty { break }
                lock.lock(); if data.count < maxBytes { data.append(chunk.prefix(maxBytes - data.count)) }; lock.unlock()
            }
        }
        reader.start()
        let deadline = Date().addingTimeInterval(timeout)
        while proc.isRunning && Date() < deadline { usleep(50_000) }
        if proc.isRunning { proc.terminate(); usleep(200_000); if proc.isRunning { kill(proc.processIdentifier, SIGKILL) } }
        proc.waitUntilExit()
        while !reader.isFinished { usleep(10_000) }
        lock.lock(); defer { lock.unlock() }
        return (proc.terminationStatus, String(decoding: data, as: UTF8.self))
    }
}
