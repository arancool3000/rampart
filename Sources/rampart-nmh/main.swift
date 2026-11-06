import Foundation
import RampartShared
import RampartWeb

// rampart-nmh: native messaging host for the RamPart browser extension (Chrome, Brave, Edge, Arc,
// Chromium). Speaks Chrome's stdio protocol: 32-bit native-endian length + UTF-8 JSON, one object
// per message. Answers verdicts locally with RampartWeb and consults rampartd over IPC when it runs.
//
// Usage:  rampart-nmh                       (launched by the browser; reads stdin until EOF)
//         rampart-nmh --check <url|text>    (prints a JSON report; for scripts and tests)
//         rampart-nmh --version

let args = CommandLine.arguments.dropFirst()
if args.first == "--version" { print(Product.version); exit(0) }

setvbuf(stdout, nil, _IOFBF, 1 << 16)
let service = WebVerdictService(bridge: IPCDaemonBridge())

if args.first == "--check", let input = args.dropFirst().first {
    let report = service.checker.check(input)
    let e = JSONEncoder(); e.outputFormatting = [.prettyPrinted, .sortedKeys]
    FileHandle.standardOutput.write(try! e.encode(report)); print()
    exit(0)
}

func send(_ resp: NMResponse) {
    guard let data = try? NativeMessaging.encode(resp) else { return }
    _ = IPC.writeFrame(fd: STDOUT_FILENO, data)
}

let decoder = JSONDecoder()
while let frame = NativeMessaging.readFrame(fd: STDIN_FILENO) {
    guard let req = try? decoder.decode(NMRequest.self, from: frame) else {
        var id: String? = nil
        if let any = try? JSONSerialization.jsonObject(with: frame) as? [String: Any] { id = any["id"] as? String ?? (any["id"] as? Int).map(String.init) }
        send(NMResponse(id: id, ok: false, error: "bad request")); continue
    }
    send(service.handle(req))
}
exit(0)
