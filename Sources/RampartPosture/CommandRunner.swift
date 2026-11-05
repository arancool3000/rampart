import Foundation

/// Result of running one read-only command.
public struct CommandResult: Sendable, Equatable {
    public var status: Int32
    public var stdout: String
    public var stderr: String
    public var timedOut: Bool
    public var launchFailed: Bool
    /// stdout followed by stderr (some tools, e.g. sysadminctl, print their answer via NSLog on stderr).
    public var combined: String { stderr.isEmpty ? stdout : (stdout.isEmpty ? stderr : stdout + "\n" + stderr) }
    public var usable: Bool { !timedOut && !launchFailed }
    public init(status: Int32 = 0, stdout: String = "", stderr: String = "", timedOut: Bool = false, launchFailed: Bool = false) {
        self.status = status; self.stdout = stdout; self.stderr = stderr; self.timedOut = timedOut; self.launchFailed = launchFailed
    }
    public static let failedToLaunch = CommandResult(status: -1, launchFailed: true)
}

/// Runs a command with an argument array (never `sh -c`) and a timeout. Injectable for tests.
public protocol CommandRunning: Sendable {
    func run(_ executable: String, _ arguments: [String], timeout: TimeInterval) -> CommandResult
}

/// Real runner based on `Process`. Kills the child (SIGTERM, then SIGKILL) when the timeout passes.
public struct ProcessRunner: CommandRunning {
    public init() {}

    private final class Box: @unchecked Sendable {
        let lock = NSLock()
        var out = Data(), err = Data()
    }

    public func run(_ executable: String, _ arguments: [String], timeout: TimeInterval) -> CommandResult {
        guard FileManager.default.isExecutableFile(atPath: executable) else { return .failedToLaunch }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: executable)
        p.arguments = arguments
        let outPipe = Pipe(), errPipe = Pipe()
        p.standardOutput = outPipe
        p.standardError = errPipe
        p.standardInput = FileHandle.nullDevice
        let finished = DispatchSemaphore(value: 0)
        p.terminationHandler = { _ in finished.signal() }
        do { try p.run() } catch { return .failedToLaunch }

        let box = Box()
        let readers = DispatchGroup()
        readers.enter()
        DispatchQueue.global(qos: .utility).async {
            let d = outPipe.fileHandleForReading.readDataToEndOfFile()
            box.lock.lock(); box.out = d; box.lock.unlock(); readers.leave()
        }
        readers.enter()
        DispatchQueue.global(qos: .utility).async {
            let d = errPipe.fileHandleForReading.readDataToEndOfFile()
            box.lock.lock(); box.err = d; box.lock.unlock(); readers.leave()
        }

        var timedOut = false
        if finished.wait(timeout: .now() + timeout) == .timedOut {
            timedOut = true
            p.terminate()
            if finished.wait(timeout: .now() + 0.5) == .timedOut {
                kill(p.processIdentifier, SIGKILL)
                _ = finished.wait(timeout: .now() + 0.5)
            }
        }
        // Grandchildren may keep the pipe open; never hang on them.
        _ = readers.wait(timeout: .now() + 1)
        box.lock.lock(); let out = box.out, err = box.err; box.lock.unlock()
        return CommandResult(status: p.isRunning ? -1 : p.terminationStatus,
                             stdout: String(decoding: out, as: UTF8.self),
                             stderr: String(decoding: err, as: UTF8.self),
                             timedOut: timedOut)
    }
}

/// Facts about the machine and file system, injectable for tests.
public struct PostureEnvironment: @unchecked Sendable {
    public var isRoot: Bool
    public var isAppleSilicon: Bool
    public var home: String
    public var userName: String
    public var now: Date
    public var fileExists: (String) -> Bool
    public var readFile: (String) -> Data?
    public var modificationDate: (String) -> Date?

    public init(isRoot: Bool, isAppleSilicon: Bool, home: String, userName: String, now: Date = Date(),
                fileExists: @escaping (String) -> Bool, readFile: @escaping (String) -> Data?,
                modificationDate: @escaping (String) -> Date?) {
        self.isRoot = isRoot; self.isAppleSilicon = isAppleSilicon; self.home = home; self.userName = userName
        self.now = now; self.fileExists = fileExists; self.readFile = readFile; self.modificationDate = modificationDate
    }

    public static func live() -> PostureEnvironment {
        var arm: Int32 = 0; var size = MemoryLayout<Int32>.size
        let isArm = sysctlbyname("hw.optional.arm64", &arm, &size, nil, 0) == 0 && arm == 1
        return PostureEnvironment(
            isRoot: getuid() == 0, isAppleSilicon: isArm,
            home: FileManager.default.homeDirectoryForCurrentUser.path, userName: NSUserName(),
            fileExists: { FileManager.default.fileExists(atPath: $0) },
            readFile: { FileManager.default.contents(atPath: $0) },
            modificationDate: { (try? FileManager.default.attributesOfItem(atPath: $0))?[.modificationDate] as? Date })
    }
}

/// Full Disk Access probe without prompting: try to open files that only FDA can read.
public enum FullDiskAccess {
    public static func isGranted(home: String = FileManager.default.homeDirectoryForCurrentUser.path) -> Bool {
        let canaries = [home + "/Library/Application Support/com.apple.TCC/TCC.db",
                        home + "/Library/Safari/Bookmarks.plist",
                        home + "/Library/Safari/CloudTabs.db"]
        for path in canaries {
            let fd = open(path, O_RDONLY)
            if fd >= 0 { close(fd); return true }
        }
        return false
    }
}
