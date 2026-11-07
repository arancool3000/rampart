import Foundation

// Locates helper products (rampartd, rampart-nmh) that live next to the running rampart-selftest binary.
// If one is missing it is built first via scripts/agent-build.sh (serialised, scratch path .build-agents),
// unless RAMPART_SELFTEST_NO_BUILD=1. Returns nil only after printing a clear SKIP line.
extension SelfTest {
    static var selfTestBinDir: URL {
        URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().deletingLastPathComponent()
    }

    /// Walks up from the binary directory to the package root (directory holding Package.swift).
    static var packageRoot: URL? {
        var dir = selfTestBinDir
        for _ in 0..<8 {
            if FileManager.default.fileExists(atPath: dir.appendingPathComponent("Package.swift").path) { return dir }
            dir = dir.deletingLastPathComponent()
        }
        return nil
    }

    static func siblingProduct(_ name: String, envOverride: String? = nil) -> String? {
        let fm = FileManager.default
        if let key = envOverride, let p = ProcessInfo.processInfo.environment[key], !p.isEmpty {
            if fm.isExecutableFile(atPath: p) { return p }
            print("SKIP \(name): \(key)=\(p) is not executable")
            return nil
        }
        let sibling = selfTestBinDir.appendingPathComponent(name).path
        if fm.isExecutableFile(atPath: sibling) && !isStale(sibling) { return sibling }
        guard ProcessInfo.processInfo.environment["RAMPART_SELFTEST_NO_BUILD"] != "1",
              let root = packageRoot else {
            print("SKIP \(name): not built at \(sibling) (build it with scripts/agent-build.sh --product \(name))")
            return nil
        }
        let script = root.appendingPathComponent("scripts/agent-build.sh").path
        print("  building \(name) via scripts/agent-build.sh ...")
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/zsh")
        p.arguments = [script, "--product", name]
        p.currentDirectoryURL = root
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        do { try p.run(); p.waitUntilExit() } catch {
            print("SKIP \(name): could not run \(script): \(error)"); return nil
        }
        // agent-build.sh writes to .build-agents; take the newest of the sibling path and that output dir.
        let built = [sibling, root.appendingPathComponent(".build-agents/out/Products/Debug/\(name)").path]
        func mtime(_ x: String) -> Date { ((try? fm.attributesOfItem(atPath: x))?[.modificationDate] as? Date) ?? .distantPast }
        if let hit = built.filter({ fm.isExecutableFile(atPath: $0) }).max(by: { mtime($0) < mtime($1) }) { return hit }
        print("SKIP \(name): build via agent-build.sh did not produce \(name) (exit \(p.terminationStatus))")
        return nil
    }

    /// A sibling older than this test binary may come from an older source tree; rebuild it.
    static func isStale(_ path: String) -> Bool {
        let fm = FileManager.default
        guard let me = (try? fm.attributesOfItem(atPath: selfTestBinDir.appendingPathComponent(
                  URL(fileURLWithPath: CommandLine.arguments[0]).lastPathComponent).path))?[.modificationDate] as? Date,
              let it = (try? fm.attributesOfItem(atPath: path))?[.modificationDate] as? Date else { return false }
        return it.addingTimeInterval(600) < me
    }
}
