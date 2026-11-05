import Foundation
import RampartShared

// rampart — command-line client for rampartd (or in-process with --local).

setvbuf(stdout, nil, _IOLBF, 0)
signal(SIGPIPE, SIG_IGN)

let usage = """
rampart \(Product.version) — Rampart antivirus command line

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

// Commands that don't need a transport.
switch command {
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
    print("Rampart \(Product.version)\(local ? " (local)" : "")")
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

default:
    fail("unknown command '\(command)'. Run `rampart --help`.")
}
exit(0)
