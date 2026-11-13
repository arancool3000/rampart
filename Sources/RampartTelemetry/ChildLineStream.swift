import Foundation
import RampartShared

/// Splits a byte stream into newline-terminated lines. Oversized lines are dropped (counted) instead of
/// growing the buffer without bound. Not thread-safe; feed it from one queue.
public final class LineSplitter {
    public let maxLineBytes: Int
    public private(set) var droppedOversized = 0
    private var buffer = Data()
    private var discarding = false

    public init(maxLineBytes: Int = 8 * 1024 * 1024) { self.maxLineBytes = maxLineBytes }

    /// Appends bytes and returns every complete line (without the trailing newline / CR).
    public func feed(_ data: Data) -> [Data] {
        var lines: [Data] = []
        var chunk = data[...]
        while let nl = chunk.firstIndex(of: 0x0A) {
            let part = chunk[chunk.startIndex..<nl]
            if discarding {
                discarding = false
            } else if buffer.count + part.count <= maxLineBytes {
                var line = buffer; line.append(contentsOf: part); buffer.removeAll(keepingCapacity: true)
                if line.last == 0x0D { line.removeLast() }
                if !line.isEmpty { lines.append(line) }
            } else {
                droppedOversized += 1
            }
            buffer.removeAll(keepingCapacity: true)
            chunk = chunk[chunk.index(after: nl)...]
        }
        if !chunk.isEmpty && !discarding {
            if buffer.count + chunk.count > maxLineBytes {
                buffer.removeAll(); discarding = true; droppedOversized += 1
            } else {
                buffer.append(contentsOf: chunk)
            }
        }
        return lines
    }

    /// Forgets any partial line and discards bytes up to the next newline. Called after bytes were dropped
    /// (backpressure), so the tail of a cut line is never glued onto the head of another one.
    public func resync() {
        buffer.removeAll(keepingCapacity: true); discarding = true
    }

    /// Returns any unterminated trailing line (used at EOF).
    public func flush() -> Data? {
        defer { buffer.removeAll(); discarding = false }
        return (buffer.isEmpty || discarding) ? nil : buffer
    }
}

/// Runs a child process, streams its stdout as lines, and restarts it with exponential backoff
/// if it exits while still wanted. Used by `EsloggerSource` and `UnifiedLogSource`.
public final class ChildLineStream {
    public let executable: String
    public let arguments: [String]
    public var maxBackoff: TimeInterval = 60
    /// Called on `queue` for every line.
    public var onLine: ((Data) -> Void)?
    /// Called on `queue` when the child exits: (status, captured stderr tail).
    public var onExit: ((Int32, String) -> Void)?
    /// When false the child is not relaunched after it exits.
    public var restartOnExit = true
    /// Backpressure (wms-o6): bytes read from the child but not yet split and handled are capped. When the consumer
    /// falls behind (an attacker floods eslogger with cheap events), whole chunks are dropped and counted instead of
    /// queueing without bound; the stream then resynchronises at the next newline and `onGap` reports the loss.
    public var maxPendingBytes = 64 * 1024 * 1024
    /// Called on `queue` once per contiguous run of dropped chunks, with the total bytes dropped so far.
    public var onGap: ((Int) -> Void)?
    private let pendingLock = NSLock()
    private var pendingBytes = 0
    private var dropEpoch = 0
    private var droppedBytesSinceGap = 0
    private var _droppedBackpressureBytes = 0
    private var seenEpoch = 0
    /// Total bytes dropped because the consumer could not keep up.
    public var droppedBackpressureBytes: Int { pendingLock.withLock { _droppedBackpressureBytes } }

    public let queue: DispatchQueue
    private var process: Process?
    private var splitter: LineSplitter
    private var stderrTail = Data()
    private var wanted = false
    private var backoff: TimeInterval = 1
    private var generation = 0
    public private(set) var launches = 0
    public private(set) var lastStartDate: Date?
    private let log = RLog.logger("telemetry.child")

    public init(executable: String, arguments: [String], label: String, maxLineBytes: Int = 8 * 1024 * 1024) {
        self.executable = executable
        self.arguments = arguments
        self.queue = DispatchQueue(label: "app.rampart.telemetry.\(label)")
        self.splitter = LineSplitter(maxLineBytes: maxLineBytes)
    }

    public var isRunning: Bool { queue.sync { process?.isRunning ?? false } }
    public var droppedOversizedLines: Int { queue.sync { splitter.droppedOversized } }

    public func start() throws {
        try queue.sync {
            wanted = true
            backoff = 1
            try launchLocked()
        }
    }

    public func stop() {
        queue.sync {
            wanted = false
            generation += 1
            if let p = process {
                (p.standardOutput as? Pipe)?.fileHandleForReading.readabilityHandler = nil
                (p.standardError as? Pipe)?.fileHandleForReading.readabilityHandler = nil
                p.terminationHandler = nil
                if p.isRunning {
                    p.terminate()
                    let pid = p.processIdentifier
                    // Escalate if the child ignores SIGTERM.
                    DispatchQueue.global().asyncAfter(deadline: .now() + 2) { if kill(pid, 0) == 0 { kill(pid, SIGKILL) } }
                }
            }
            process = nil
        }
    }

    /// Reader side: admits a chunk if the backlog stays under `maxPendingBytes`; otherwise drops it and starts a
    /// new drop epoch so the first chunk admitted afterwards triggers a resync at exactly the right place.
    func admit(_ n: Int) -> (Bool, Int) {
        pendingLock.lock(); defer { pendingLock.unlock() }
        if n > 0, pendingBytes + n > maxPendingBytes {
            if droppedBytesSinceGap == 0 { dropEpoch += 1 }
            droppedBytesSinceGap += n; _droppedBackpressureBytes += n
            return (false, dropEpoch)
        }
        pendingBytes += n
        droppedBytesSinceGap = 0
        return (true, dropEpoch)
    }

    /// Queue side: returns (bytes lost before this chunk, whether to resync) the first time a new epoch is seen.
    private func release(_ n: Int, epoch: Int) -> (Int, Bool) {
        pendingLock.lock(); defer { pendingLock.unlock() }
        pendingBytes -= n
        guard epoch != seenEpoch else { return (0, false) }
        seenEpoch = epoch
        return (_droppedBackpressureBytes, true)
    }

    /// Test hook: feeds bytes through the same admission / resync path as the child's stdout.
    public func simulateOutput(_ data: Data, consumerDelay: TimeInterval = 0) {
        let (admitted, epoch) = admit(data.count)
        guard admitted else { return }
        queue.async {
            if consumerDelay > 0 { Thread.sleep(forTimeInterval: consumerDelay) }
            let (gapBytes, resync) = self.release(data.count, epoch: epoch)
            if resync { self.splitter.resync(); self.onGap?(gapBytes) }
            for line in self.splitter.feed(data) { self.onLine?(line) }
        }
    }

    /// Waits until every queued chunk has been handled (tests).
    public func drainForTest() { queue.sync {} }

    private func launchLocked() throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: executable)
        p.arguments = arguments
        p.standardInput = FileHandle.nullDevice
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        let gen = generation
        splitter = LineSplitter(maxLineBytes: splitter.maxLineBytes)
        stderrTail.removeAll()
        out.fileHandleForReading.readabilityHandler = { [weak self] h in
            let data = h.availableData
            guard let self else { return }
            // Admission control: never let unprocessed output grow without bound.
            let (admitted, epoch) = self.admit(data.count)
            guard admitted else { return }
            self.queue.async {
                let (gapBytes, resync) = self.release(data.count, epoch: epoch)
                guard gen == self.generation else { return }
                if resync {
                    self.splitter.resync()
                    self.onGap?(gapBytes)
                }
                if data.isEmpty {
                    h.readabilityHandler = nil
                    if let rest = self.splitter.flush() { self.onLine?(rest) }
                    return
                }
                for line in self.splitter.feed(data) { self.onLine?(line) }
            }
        }
        err.fileHandleForReading.readabilityHandler = { [weak self] h in
            let data = h.availableData
            guard let self else { return }
            if data.isEmpty { h.readabilityHandler = nil; return }
            self.queue.async {
                self.stderrTail.append(data)
                if self.stderrTail.count > 4096 { self.stderrTail = self.stderrTail.suffix(4096) }
            }
        }
        p.terminationHandler = { [weak self] proc in
            guard let self else { return }
            let status = proc.terminationStatus
            // Give the stdout handler a moment to drain before reporting.
            self.queue.asyncAfter(deadline: .now() + 0.2) {
                guard gen == self.generation else { return }
                let tail = String(decoding: self.stderrTail, as: UTF8.self)
                self.process = nil
                self.onExit?(status, tail)
                guard self.wanted, self.restartOnExit else { return }
                let ranFor = Date().timeIntervalSince(self.lastStartDate ?? .distantPast)
                if ranFor > 60 { self.backoff = 1 }
                let delay = self.backoff
                self.backoff = min(self.backoff * 2, self.maxBackoff)
                self.log.info("\(self.executable, privacy: .public) exited \(status), restarting in \(delay)s")
                self.generation += 1
                let next = self.generation
                self.queue.asyncAfter(deadline: .now() + delay) {
                    guard self.wanted, next == self.generation else { return }
                    do { try self.launchLocked() } catch { self.log.error("relaunch failed: \(error.localizedDescription, privacy: .public)") }
                }
            }
        }
        try p.run()
        process = p
        launches += 1
        lastStartDate = Date()
    }
}
