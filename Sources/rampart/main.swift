import Foundation
import RampartShared

// rampart — command-line client for rampartd (or in-process with --local).

setvbuf(stdout, nil, _IOLBF, 0)
signal(SIGPIPE, SIG_IGN)

let usage = """
rampart \(Product.version) — \(Product.name) antivirus command line

usage: rampart [--json] [--local [--root DIR] [--report-only]] [--user | --socket PATH] <command>

commands:
  status                              protection status
  scan [--quick] [PATH ...]           scan paths (no paths: full scan; --quick: common locations)
  detections                          detection history
  quarantine list                     quarantined items
  quarantine add <detection-id>       quarantine a detected file
  quarantine restore <id> [--allow]   restore (and optionally trust its hash)
  quarantine delete <id>              delete permanently
  allow <sha256>                      trust a file hash
  persistence                         login items, launch agents/daemons, extensions, ...
  posture                             security checks and score
  posture fix <check-id>              apply a safe one-click fix (daemon, admin)
  web on|off                          DNS web protection
  update                              update signatures / rules / blocklists
  eicar [PATH]                        write the harmless EICAR test file (default ./com.rampart.test.eicar.com)
  events                              stream live detections from the daemon
  activity [N]                        protection activity log (newest first, default 30)
  connections                         live network connections with process, signing and host
  wifi                                Wi-Fi security and gateway check
  net                                 web protection statistics
  settings get                        daemon settings
  settings set key=value ...          change settings (e.g. realtimeOn=false exclusions=/a,/b)
  realtime on|off                     real-time protection
  scan-control pause|resume|cancel    control the running scan
  fix <persistence-id> [--apply]      preview (default) or apply removal of a persistence item
  rules [list]                        allow rules
  rules add hash|developer|folder|signing <value> [name]
  rules remove <id>
  health                              daemon mode, uptime, CPU, memory, event sources, recent errors
  remote [report|allow <id> [min]|revoke <id>|lockdown on|off]   remote-access lockdown
  tamper                              tamper-protection status
  check-url <url>                     URL verdict (lookalikes, blocklists, punycode, ...)
  scam <text|url> [--kind K]          scam check of a message, email or URL
  web-lookup <host>                   is this host on the daemon's blocklists?
  install --gui-auth [--app PATH]     "Enable full protection": one admin password dialog installs the
                                      root daemon (without --gui-auth or with --dry-run: print the command)
  uninstall --gui-auth [--keep-data]  remove everything (one admin dialog), verified clean
  version

options:
  --json          machine-readable output
  --local         run in this process instead of talking to rampartd (per-user state)
  --root DIR      state folder for --local (default ~/Library/Application Support/Rampart)
  --report-only   with --local: record detections but never quarantine
  --user          talk to a development daemon started with `rampartd --user`
  --socket PATH   explicit daemon socket
exit codes: 0 ok / clean, 1 threats found, 2 error
"""

var args = Array(CommandLine.arguments.dropFirst())
func flag(_ f: String) -> Bool { if let i = args.firstIndex(of: f) { args.remove(at: i); return true }; return false }
func option(_ f: String) -> String? {
    guard let i = args.firstIndex(of: f), i + 1 < args.count else { return nil }
    let v = args[i + 1]; args.removeSubrange(i...i + 1); return v
}
func fail(_ msg: String, code: Int32 = 2) -> Never { FileHandle.standardError.write(Data("rampart: \(msg)\n".utf8)); exit(code) }
func err(_ msg: String) { FileHandle.standardError.write(Data(msg.utf8)) }

let json = flag("--json")
let local = flag("--local")
let reportOnly = flag("--report-only")
let useUser = flag("--user")
let socketPath = option("--socket")
let rootDir = option("--root").map { URL(fileURLWithPath: ($0 as NSString).expandingTildeInPath) }
if flag("--help") || flag("-h") || args.isEmpty { print(usage); exit(args.isEmpty ? 0 : 0) }
let command = args.removeFirst()

func emitJSON<T: Encodable>(_ v: T) {
    let enc = JSONEncoder.rampart; enc.outputFormatting = [.prettyPrinted, .sortedKeys]
    print(String(data: (try? enc.encode(v)) ?? Data("null".utf8), encoding: .utf8)!)
}

let dateFmt: DateFormatter = { let f = DateFormatter(); f.dateStyle = .short; f.timeStyle = .short; return f }()
func fmt(_ d: Date?) -> String { d.map { dateFmt.string(from: $0) } ?? "never" }
func pad(_ s: String, _ n: Int) -> String { s.count >= n ? String(s.prefix(n)) : s + String(repeating: " ", count: n - s.count) }

/// Shell single-quote.
func shq(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }
/// AppleScript string literal body.
func asq(_ s: String) -> String { s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") }

/// The app bundle this CLI belongs to (Contents/Helpers/rampart), else /Applications/Rampart.app.
func locateApp(_ explicit: String?) -> String? {
    if let e = explicit { return (e as NSString).expandingTildeInPath }
    let me = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
    let bundle = me.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    if bundle.pathExtension == "app", FileManager.default.fileExists(atPath: bundle.appendingPathComponent("Contents/Resources/rampart-setup.sh").path) {
        return bundle.path
    }
    for c in ["/Applications/Rampart.app", "/Applications/\(Product.name).app"]
    where FileManager.default.fileExists(atPath: c + "/Contents/Resources/rampart-setup.sh") { return c }
    return nil
}

// Commands that don't need a transport.
switch command {
case "install", "uninstall":
    // One administrator authorization; afterwards the root daemon does every privileged task without prompts.
    let guiAuth = flag("--gui-auth"), dry = flag("--dry-run"), keepData = flag("--keep-data")
    let appArg = option("--app")
    guard let src = locateApp(appArg) else { fail("can't find Rampart.app (pass --app /path/to/Rampart.app)") }
    let dest = "/Applications/Rampart.app"
    var script: String
    if command == "install" {
        script = ""
        if (src as NSString).standardizingPath != dest {
            script += "/bin/launchctl bootout system/app.rampart.daemon 2>/dev/null; /bin/rm -rf \(shq(dest)) && /usr/bin/ditto \(shq(src)) \(shq(dest)) && /usr/sbin/chown -R root:wheel \(shq(dest)) && /usr/bin/xattr -dr com.apple.quarantine \(shq(dest)) 2>/dev/null; "
        }
        script += "RAMPART_APP=\(shq(dest)) /bin/bash \(shq(dest + "/Contents/Resources/rampart-setup.sh")) install"
    } else {
        let setup = FileManager.default.fileExists(atPath: dest + "/Contents/Resources/rampart-setup.sh") ? dest + "/Contents/Resources/rampart-setup.sh" : src + "/Contents/Resources/rampart-setup.sh"
        script = "/bin/bash \(shq(setup)) uninstall\(keepData ? " --keep-data" : "")"
    }
    let prompt = command == "install"
        ? "\(Product.name) needs your permission once to install its protection service."
        : "\(Product.name) needs your permission to remove its protection service."
    let apple = "do shell script \"\(asq(script))\" with administrator privileges with prompt \"\(asq(prompt))\""
    if !dry && guiAuth && Privileged.noPrivilegedTools { fail("refusing to show an administrator dialog (RAMPART_NO_PRIVILEGED_TOOLS=1); use --dry-run") }
    if dry || !guiAuth {
        if json { emitJSON(["shell": script, "osascript": apple]); exit(0) }
        print(guiAuth ? "Would run (one administrator prompt):" : "Run this with sudo, or pass --gui-auth for a password dialog:")
        print(guiAuth ? "  /usr/bin/osascript -e \(shq(apple))" : "  sudo /bin/sh -c \(shq(script))")
        exit(0)
    }
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
    p.arguments = ["-e", apple]
    let errPipe = Pipe(); p.standardError = errPipe
    do { try p.run() } catch { fail("couldn't start osascript: \(error.localizedDescription)") }
    p.waitUntilExit()
    let errText = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    if p.terminationStatus != 0 {
        if errText.contains("-128") { fail("cancelled", code: 3) }
        fail("\(command) failed: \(errText.trimmingCharacters(in: .whitespacesAndNewlines))")
    }
    if json { emitJSON(["ok": true]) } else { print(command == "install" ? "\(Product.name) system protection is installed." : "\(Product.name) was removed.") }
    exit(0)
case "version", "--version":
    print("rampart \(Product.version)"); exit(0)
case "eicar":
    let path = args.first.map { ($0 as NSString).expandingTildeInPath }
        ?? FileManager.default.currentDirectoryPath + "/com.rampart.test.eicar.com"
    do {
        try Eicar.data.write(to: URL(fileURLWithPath: path), options: .withoutOverwriting)
        if json { emitJSON(["path": path]) } else {
            print("Wrote the EICAR test file to \(path)")
            print("It is harmless; every antivirus detects it by design. Scan it with: rampart scan \"\(path)\"")
        }
        exit(0)
    } catch { fail("could not write \(path): \(error.localizedDescription)") }
default: break
}

let transport: Transport
if local {
    transport = LocalTransport(root: rootDir, remediate: !reportOnly)
} else {
    do { transport = try SocketTransport.resolve(explicit: socketPath, user: useUser) } catch { fail(error.localizedDescription) }
}

/// Runs a request and returns the terminal response.
func call(_ r: IPCRequest, progress: ((IPCResponse) -> Void)? = nil) -> IPCResponse {
    var final: IPCResponse = .error("no response")
    do {
        try transport.request(r) { resp in
            if resp.isTerminal { final = resp; return false }
            progress?(resp); return true
        }
    } catch { fail(error.localizedDescription) }
    if case .error(let m) = final { if json { emitJSON(["error": m]) }; fail(m) }
    return final
}

func expectOK(_ r: IPCRequest, _ message: String) {
    if case .ok = call(r) { if json { emitJSON(["ok": true]) } else { print(message) } } else { fail("unexpected response") }
}

func printDetections(_ ds: [Detection]) {
    if ds.isEmpty { print("No threats found."); return }
    for d in ds {
        let state = d.resolved ? "resolved" : "open"
        print("\(d.severity.label.uppercased())  \(d.name)  [\(d.category.rawValue), confidence \(d.confidence)%, \(state)]")
        if let p = d.path { print("    file: \(p)") }
        if let pid = d.pid { print("    pid:  \(pid)") }
        print("    id:   \(d.id.uuidString)")
        for e in d.evidence { print("    - \(e.title) (\(e.source.rawValue), \(e.score)): \(e.detail)") }
    }
}

func parseUUID(_ s: String?) -> UUID {
    guard let s, let u = UUID(uuidString: s) else { fail("expected an id (UUID)") }
    return u
}

let isTTY = isatty(STDERR_FILENO) != 0

switch command {
case "status":
    guard case .status(let s) = call(.status) else { fail("unexpected response") }
    if json { emitJSON(s); break }
    print("\(Product.name) \(Product.version)\(local ? " (local)" : "")")
    print("  Real-time protection: \(s.realtimeOn ? "on" : "off")")
    for (k, v) in s.sources.sorted(by: { $0.key < $1.key }) { print("    \(pad(k, 16)) \(v ? "running" : "not running")") }
    print("  Web protection:       \(s.webProtectionOn ? "on" : "off")")
    print("  Full Disk Access:     \(s.fullDiskAccess ? "granted" : "not granted")")
    print("  Last scan:            \(fmt(s.lastScan))")
    print("  Signatures:           \(s.signatureVersion)")
    print("  XProtect:             \(s.xprotectVersion ?? "unknown")")
    print("  Security score:       \(s.securityScore.map(String.init) ?? "not checked")")
    print("  Open threats:         \(s.openDetections)")

case "scan":
    let quick = args.first == "--quick" ? (args.removeFirst() == "--quick") : false
    let paths = args.map { p -> String in
        let e = (p as NSString).expandingTildeInPath
        return e.hasPrefix("/") ? e : FileManager.default.currentDirectoryPath + "/" + e
    }
    let r = call(.scan(paths: paths, quick: quick)) { resp in
        if !json, isTTY, case .scanProgress(let n, let total, let cur) = resp {
            err("\r\u{1B}[K  scanned \(n)/\(total)  \(String(cur.suffix(60)))")
        }
    }
    if !json && isTTY { err("\r\u{1B}[K") }
    guard case .scanFinished(let n, let ds, let secs) = r else { fail("unexpected response") }
    if json {
        struct Out: Encodable { var scanned: Int; var seconds: Double; var detections: [Detection] }
        emitJSON(Out(scanned: n, seconds: secs, detections: ds))
    } else {
        print("Scanned \(n) files in \(String(format: "%.1f", secs)) s — \(ds.count) detection\(ds.count == 1 ? "" : "s").")
        if !ds.isEmpty { printDetections(ds) }
        for d in ds where d.resolved { print("  \(d.name): quarantined") }
    }
    exit(ds.isEmpty ? 0 : 1)

case "detections":
    guard case .detections(let ds) = call(.listDetections) else { fail("unexpected response") }
    if json { emitJSON(ds) } else { printDetections(ds) }

case "quarantine":
    let sub = args.first ?? "list"
    if !args.isEmpty { args.removeFirst() }
    switch sub {
    case "list":
        guard case .quarantine(let qs) = call(.listQuarantine) else { fail("unexpected response") }
        if json { emitJSON(qs); break }
        if qs.isEmpty { print("Quarantine is empty.") }
        for q in qs.sorted(by: { $0.date > $1.date }) {
            print("\(q.id.uuidString)  \(fmt(q.date))  \(q.detectionName)")
            print("    from \(q.originalPath)  (\(q.size) bytes, sha256 \(q.sha256.prefix(16))…)")
        }
    case "add": expectOK(.quarantine(detectionID: parseUUID(args.first)), "Quarantined.")
    case "restore":
        let allow = flag("--allow")
        expectOK(.restore(id: parseUUID(args.first), allow: allow), allow ? "Restored and trusted." : "Restored.")
    case "delete": expectOK(.deleteQuarantined(id: parseUUID(args.first)), "Deleted permanently.")
    default: fail("unknown quarantine subcommand '\(sub)'")
    }

case "allow":
    guard let h = args.first else { fail("usage: rampart allow <sha256>") }
    expectOK(.allow(sha256: h), "Trusted \(h).")

case "persistence":
    guard case .persistence(let items) = call(.persistence) else { fail("unexpected response") }
    if json { emitJSON(items); break }
    print("\(items.count) persistence items")
    for i in items.sorted(by: { ($0.kind.rawValue, $0.label) < ($1.kind.rawValue, $1.label) }) {
        let sig = i.signing.map { " [\($0.status.rawValue)\($0.teamID.map { " " + $0 } ?? "")]" } ?? ""
        print("  \(pad(i.kind.rawValue, 16)) \(i.label)\(sig)")
        print("  \(pad("", 16)) id: \(i.id)")
        print("  \(pad("", 16)) \(i.location)\(i.target.map { " -> " + $0 } ?? "")")
    }

case "posture":
    if args.first == "fix" {
        args.removeFirst()
        guard let id = args.first else { fail("usage: rampart posture fix <check-id>") }
        expectOK(.fixPosture(checkID: id), "Applied fix for \(id).")
        break
    }
    guard case .posture(let checks) = call(.posture) else { fail("unexpected response") }
    if json { emitJSON(checks); break }
    let scored = checks.filter { $0.state == .pass || $0.state == .fail }
    let total = scored.reduce(0) { $0 + $1.weight }, got = scored.filter { $0.state == .pass }.reduce(0) { $0 + $1.weight }
    if total > 0 { print("Security score: \(Int((Double(got) / Double(total) * 100).rounded()))/100") }
    for c in checks {
        let mark = ["pass": "ok  ", "fail": "FAIL", "unknown": "?   ", "notApplicable": "n/a "][c.state.rawValue] ?? "?"
        print("  \(mark) \(pad(c.title, 40)) \(c.detail)")
        if c.state == .fail && !c.fixHint.isEmpty { print("       fix: \(c.fixHint)\(c.fixable ? "  (rampart posture fix \(c.id))" : "")") }
    }

case "web":
    guard let v = args.first, v == "on" || v == "off" else { fail("usage: rampart web on|off") }
    expectOK(.setWebProtection(on: v == "on"), "Web protection \(v).")

case "update":
    expectOK(.updateSignatures, "Update finished.")

case "events":
    if !json { print("Waiting for detections (Ctrl-C to stop)…") }
    do {
        try transport.request(.subscribeEvents) { resp in
            switch resp {
            case .event(let d): if json { emitJSON(d) } else { printDetections([d]) }
            case .error(let m): fail(m)
            default: break
            }
            return true
        }
    } catch { fail(error.localizedDescription) }

case "activity":
    let n = args.first.flatMap { Int($0) } ?? 30
    guard case .activity(let es) = call(.activity(limit: n)) else { fail("unexpected response") }
    if json { emitJSON(es); break }
    if es.isEmpty { print("No activity yet.") }
    for e in es {
        print("\(fmt(e.date))  \(pad(e.kind.rawValue, 11)) \(e.title)\(e.outcome.isEmpty ? "" : "  [\(e.outcome)]")")
        if !e.detail.isEmpty { print("    \(e.detail)") }
    }

case "connections":
    guard case .connections(let cs) = call(.connections) else { fail("unexpected response") }
    if json { emitJSON(cs); break }
    print("\(cs.count) connections\(cs.contains { $0.flagged } ? " (\(cs.filter(\.flagged).count) flagged)" : "")")
    for c in cs {
        let host = c.remoteHost.map { " (\($0))" } ?? ""
        print("\(c.flagged ? "!" : " ") \(pad(c.processName, 22)) \(pad(String(c.pid), 6)) \(c.proto) \(c.remoteAddress):\(c.remotePort)\(host)  \(c.state ?? "")  \(c.signing?.rawValue ?? "")")
    }

case "wifi":
    guard case .wifi(let w) = call(.wifi) else { fail("unexpected response") }
    if json { emitJSON(w); break }
    print("Wi-Fi: \(w.connected ? "connected" : "not connected")\(w.ssid.map { " to \($0)" } ?? "")")
    if let sec = w.security { print("  Security: \(sec)\(w.weakSecurity ? " (WEAK)" : "")") }
    if let g = w.gatewayIP { print("  Gateway:  \(g)\(w.gatewayMACChanged ? "  — gateway hardware address CHANGED" : "")") }
    if let n = w.note { print("  Note: \(n)") }

case "net":
    guard case .networkStats(let n) = call(.networkStats) else { fail("unexpected response") }
    if json { emitJSON(n); break }
    print("Web protection: \(n.webProtectionOn ? "on" : "off")\(n.webProtectionAvailable ? "" : " (needs the \(Product.name) system service)")")
    print("  Blocked today: \(n.blockedToday), this month: \(n.blockedThisMonth)")
    print("  Last 14 days: \(n.blockedByDay.map(String.init).joined(separator: " "))")
    print("  Blocklist domains: \(n.blocklistDomains), updated \(fmt(n.blocklistsUpdated))")
    if !n.recentBlocks.isEmpty { print("  Recent: \(n.recentBlocks.prefix(10).joined(separator: ", "))") }

case "settings":
    let sub = args.first ?? "get"
    if !args.isEmpty { args.removeFirst() }
    guard case .settings(var cur) = call(.getSettings) else { fail("unexpected response") }
    if sub == "set" {
        guard !args.isEmpty else { fail("usage: rampart settings set key=value ...") }
        // Round-trip through JSON so every RampartSettings key is settable by name.
        var dict = (try? JSONSerialization.jsonObject(with: JSONEncoder.rampart.encode(cur))) as? [String: Any] ?? [:]
        for kv in args {
            let parts = kv.split(separator: "=", maxSplits: 1).map(String.init)
            guard parts.count == 2, let old = dict[parts[0]] else { fail("unknown setting '\(kv)'. Keys: \(dict.keys.sorted().joined(separator: ", "))") }
            let v = parts[1]
            switch old {
            case is [Any]: dict[parts[0]] = v.isEmpty ? [] : v.split(separator: ",").map(String.init)
            case let n as NSNumber where CFGetTypeID(n) == CFBooleanGetTypeID():
                guard ["true", "false", "on", "off", "1", "0"].contains(v) else { fail("\(parts[0]) needs true/false") }
                dict[parts[0]] = ["true", "on", "1"].contains(v)
            case is NSNumber: guard let i = Int(v) else { fail("\(parts[0]) needs a number") }; dict[parts[0]] = i
            default: dict[parts[0]] = v
            }
        }
        guard let data = try? JSONSerialization.data(withJSONObject: dict),
              let new = try? JSONDecoder.rampart.decode(RampartSettings.self, from: data) else { fail("invalid settings") }
        guard case .settings(let saved) = call(.setSettings(new)) else { fail("unexpected response") }
        cur = saved
    } else if sub != "get" { fail("usage: rampart settings get | set key=value ...") }
    if json { emitJSON(cur); break }
    let dict = (try? JSONSerialization.jsonObject(with: JSONEncoder.rampart.encode(cur))) as? [String: Any] ?? [:]
    for k in dict.keys.sorted() {
        let v = dict[k]!
        let shown: String
        if let a = v as? [Any] { shown = a.map { "\($0)" }.joined(separator: ",") }
        else if let n = v as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() { shown = n.boolValue ? "true" : "false" }
        else { shown = "\(v)" }
        print("  \(pad(k, 20)) \(shown)")
    }

case "realtime":
    guard let v = args.first, v == "on" || v == "off" else { fail("usage: rampart realtime on|off") }
    expectOK(.setRealtime(on: v == "on"), "Real-time protection \(v).")

case "scan-control":
    switch args.first {
    case "pause": expectOK(.pauseScan(paused: true), "Scan paused.")
    case "resume": expectOK(.pauseScan(paused: false), "Scan resumed.")
    case "cancel": expectOK(.cancelScan, "Scan cancelled.")
    default: fail("usage: rampart scan-control pause|resume|cancel")
    }

case "fix":
    let apply = flag("--apply")
    guard let id = args.first else { fail("usage: rampart fix <persistence-id> [--apply]  (ids: rampart persistence)") }
    guard case .remediationPreview(let pv) = call(.previewRemediation(persistenceID: id)) else { fail("unexpected response") }
    if json && !apply { emitJSON(pv); break }
    if !json {
        print(pv.title)
        for st in pv.steps { print("  - \(st)") }
        for c in pv.commands { print("    $ \(c)") }
        print("  Undoable: \(pv.undoable ? "yes" : "no")\(pv.requiresRoot ? "; needs root" : "")")
    }
    if apply { expectOK(.remediate(persistenceID: id), "Removed.") }
    else if !json { print("Preview only. Re-run with --apply to remove it.") }

case "rules":
    let sub = args.first ?? "list"
    if !args.isEmpty { args.removeFirst() }
    var resp: IPCResponse
    switch sub {
    case "list": resp = call(.listAllowRules)
    case "add":
        guard args.count >= 2 else { fail("usage: rampart rules add hash|developer|folder|signing <value> [name]") }
        let scope: AllowRuleSpec.Scope
        switch args[0] {
        case "hash": scope = .fileHash; case "developer", "team": scope = .developer
        case "folder": scope = .folder; case "signing", "signingID": scope = .signingID
        default: fail("scope must be hash, developer, folder or signing")
        }
        var value = args[1]
        if scope == .folder { value = (value as NSString).expandingTildeInPath; if !value.hasPrefix("/") { value = FileManager.default.currentDirectoryPath + "/" + value } }
        resp = call(.addAllowRule(AllowRuleSpec(scope: scope, value: value, name: args.dropFirst(2).joined(separator: " "))))
    case "remove": resp = call(.removeAllowRule(id: parseUUID(args.first)))
    default: fail("usage: rampart rules [list|add|remove]")
    }
    guard case .allowRules(let rules) = resp else { fail("unexpected response") }
    if json { emitJSON(rules); break }
    if rules.isEmpty { print("No allow rules.") }
    for r in rules { print("\(r.id.uuidString)  \(pad(r.scope.rawValue, 9)) \(r.value)\(r.name.isEmpty ? "" : "  (\(r.name))")") }

case "remote":
    switch args.first ?? "report" {
    case "allow":
        guard args.count >= 2 else { fail("usage: rampart remote allow <tool-id> [minutes]") }
        expectOK(.allowRemoteTool(id: args[1], minutes: args.count > 2 ? Int(args[2]) : nil), "Allowed \(args[1]).")
    case "revoke":
        guard args.count >= 2 else { fail("usage: rampart remote revoke <tool-id>") }
        expectOK(.revokeRemoteTool(id: args[1]), "Revoked \(args[1]).")
    case "lockdown":
        guard args.count >= 2, ["on", "off"].contains(args[1]) else { fail("usage: rampart remote lockdown on|off") }
        expectOK(.setRemoteLockdown(on: args[1] == "on"), "Remote-access lockdown \(args[1]).")
    default:
        guard case .remoteAccess(let data) = call(.remoteAccessReport) else { fail("unexpected response") }
        if json { print(String(data: data, encoding: .utf8) ?? "{}"); break }
        let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
        print("Remote-access lockdown: \((obj["lockdownEnabled"] as? Bool) == true ? "on" : "off")")
        for f in (obj["findings"] as? [[String: Any]]) ?? [] {
            print("  \(f["name"] ?? "?") [\(f["toolID"] ?? "")]  active=\((f["active"] as? Bool) == true) allowed=\((f["allowed"] as? Bool) == true)")
        }
        if let n = obj["note"] as? String, !n.isEmpty { print("  \(n)") }
    }

case "check-url", "scam":
    guard let input = args.first else { fail("usage: rampart check-url <url> | rampart scam <text|url> [--kind message|email|url]") }
    let kind = option("--kind") ?? "auto"
    let r = command == "check-url" ? call(.checkURL(url: input)) : call(.scamCheck(text: input, kind: kind))
    switch r {
    case .urlVerdict(let d), .scamReport(let d):
        if json { print(String(data: d, encoding: .utf8) ?? "{}"); break }
        let o = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] ?? [:]
        print("Verdict: \(o["verdict"] ?? "?")  score \(o["score"] ?? "?")")
        if let h = o["headline"] as? String { print("  \(h)") }
        for sig in (o["signals"] as? [[String: Any]]) ?? [] { print("  - \(sig["title"] ?? "")  (\(sig["score"] ?? ""))") }
    default: fail("unexpected response")
    }

case "web-lookup":
    guard let host = args.first else { fail("usage: rampart web-lookup <host>") }
    guard case .webLookup(let d) = call(.webLookup(host: host)) else { fail("unexpected response") }
    if let d { print(String(data: d, encoding: .utf8) ?? "") } else { print(json ? "null" : "\(host): not on any blocklist") }

case "tamper":
    guard case .tamper(let data) = call(.tamperStatus) else { fail("unexpected response") }
    print(String(data: data, encoding: .utf8) ?? "{}")

case "health":
    guard case .health(let h) = call(.health) else { fail("unexpected response") }
    if json { emitJSON(h); break }
    print("rampartd \(h.version), \(h.mode) mode, up \(Int(h.uptimeSeconds)) s")
    print("  CPU \(h.cpuPercent)%, memory \(h.residentMB) MB")
    for (k, v) in h.sources.sorted(by: { $0.key < $1.key }) { print("  \(pad(k, 12)) \(v ? "running" : "not running")") }
    if !h.lastErrors.isEmpty { print("  Recent problems:"); for e in h.lastErrors.suffix(5) { print("    \(e)") } }

default:
    fail("unknown command '\(command)'. Run `rampart --help`.")
}
exit(0)
