import Foundation
import Darwin

/// A bounded decoy folder tree ("Private", "Backups", "Taxes 2025" ...) with breadcrumb notes that point to other
/// dead ends and relative symlink loops that only ever point back up *inside* the tree.
/// Hard bounds: depth ≤ 6, fan-out ≤ 3, ≤ 120 directories, ≤ 60 links. RamPart's scanner, Spotlight and
/// Time Machine are kept out (exclusion list, `.metadata_never_index`, backup-exclude xattr).
public struct MazeSpec: Sendable, Equatable {
    public var depth: Int
    public var fanout: Int
    public var maxDirs: Int
    public var seed: UInt64
    public init(depth: Int = 4, fanout: Int = 3, maxDirs: Int = 60, seed: UInt64 = 0xCA7) {
        self.depth = min(max(depth, 1), 6); self.fanout = min(max(fanout, 1), 3)
        self.maxDirs = min(max(maxDirs, 1), 120); self.seed = seed
    }
    public static let maxLinks = 60
}

public struct MazePlan: Sendable, Equatable {
    public var dirs: [String] = []                       // relative to the root, "" = root
    public var notes: [(path: String, hint: String)] = []
    public var links: [(path: String, target: String)] = [] // relative target, e.g. "../.."
    public static func == (a: MazePlan, b: MazePlan) -> Bool {
        a.dirs == b.dirs && a.notes.map(\.path) == b.notes.map(\.path) && a.links.map(\.path) == b.links.map(\.path)
    }
}

public enum DeceptionMaze {
    static let names = ["Backups", "Taxes 2025", "Old Mac", "vault", "Bank", "Wallets", "Do Not Open", "Keys", "Archive", "2019", "misc", "final_FINAL"]
    static let hints = [
        "the real passwords are in ../vault2",
        "moved everything to ../../Backups/old (for real this time)",
        "seed phrase is in the Taxes folder, page 3",
        "keys are one level deeper. probably.",
        "ok it's in Archive. or misc. one of those.",
    ]

    struct RNG { var s: UInt64; mutating func next() -> UInt64 { s = s &* 6364136223846793005 &+ 1442695040888963407; return s >> 33 } }

    /// Pure, deterministic plan (no disk access): easy to test for bounds and confinement.
    public static func plan(_ spec: MazeSpec) -> MazePlan {
        var p = MazePlan()
        var rng = RNG(s: spec.seed | 1)
        var queue: [(String, Int)] = [("", 0)]
        p.dirs.append("")
        while !queue.isEmpty, p.dirs.count < spec.maxDirs {
            let (dir, d) = queue.removeFirst()
            let hint = hints[Int(rng.next() % UInt64(hints.count))]
            p.notes.append((join(dir, "README - passwords.txt"), hint))
            if d >= 2, p.links.count < MazeSpec.maxLinks {
                // Loop back up 1..d levels: always inside the tree because d ≥ levels.
                let up = 1 + Int(rng.next() % UInt64(d))
                p.links.append((join(dir, "vault2"), Array(repeating: "..", count: up).joined(separator: "/")))
            }
            guard d < spec.depth else { continue }
            var used = Set<String>()
            for _ in 0..<spec.fanout where p.dirs.count < spec.maxDirs {
                var name = names[Int(rng.next() % UInt64(names.count))]
                if used.contains(name) { name += " (\(used.count + 1))" }
                used.insert(name)
                let child = join(dir, name)
                p.dirs.append(child); queue.append((child, d + 1))
            }
        }
        return p
    }

    static func join(_ a: String, _ b: String) -> String { a.isEmpty ? b : a + "/" + b }

    /// True when a relative symlink at `linkRel` (relative to the root) with `target` resolves inside the root.
    public static func isConfined(linkRel: String, target: String) -> Bool {
        guard !target.hasPrefix("/"), !target.contains("\0") else { return false }
        var stack = linkRel.split(separator: "/").map(String.init).dropLast()  // the link's directory
        for c in target.split(separator: "/").map(String.init) {
            switch c {
            case "", ".": continue
            case "..": if stack.isEmpty { return false }; stack.removeLast()
            default: stack.append(c)
            }
        }
        return true
    }

    /// Builds the maze under `root` (must not exist yet). Every directory, note and link is registered.
    @discardableResult
    public static func build(at root: String, spec: MazeSpec = MazeSpec(), planter: DecoyPlanter, now: Date = Date()) throws -> MazePlan {
        var st = stat()
        guard lstat(root, &st) != 0 else { throw DeceptionError.exists(root) }
        let parent = (root as NSString).deletingLastPathComponent
        try DecoyPlanter.ensureDirectory(parent, mode: 0o755)
        let plan = plan(spec)
        for rel in plan.dirs {
            let abs = rel.isEmpty ? root : root + "/" + rel
            guard mkdir(abs, 0o755) == 0 else { throw DeceptionError.io("mkdir \(abs)") }
            DecoyPlanter.markNoSyncNoBackup(abs)
            planter.registerDir(abs, root: rel.isEmpty, now: now)
        }
        // Spotlight: never index the maze.
        let never = root + "/.metadata_never_index"
        let fd = open(never, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o644); if fd >= 0 { close(fd) }
        if planter.hideFromFinder { _ = lchflags(root, UInt32(UF_HIDDEN)) }
        for n in plan.notes { try planter.plantFile(at: root + "/" + n.path, kind: .mazeNote, hint: n.hint, now: now) }
        for l in plan.links {
            guard isConfined(linkRel: l.path, target: l.target) else { throw DeceptionError.outsideRoot(l.path) }
            let abs = root + "/" + l.path
            guard symlink(l.target, abs) == 0 else { throw DeceptionError.io("symlink \(abs)") }
            planter.registerLink(abs, target: l.target, now: now)
        }
        try? planter.registry.save()
        return plan
    }
}

/// Paths every RamPart walker (scanner, Refresh, duplicate finder) must skip so it is never trapped by the maze
/// and never "finds" its own decoys. Spotlight / Time Machine are handled by on-disk markers.
public enum DeceptionExclusions {
    public static func paths(registry: DecoyRegistry) -> [String] {
        registry.mazeRoots + registry.all.filter { $0.kind.isFile }.map(\.path)
    }
    public static func shouldSkip(_ path: String, registry: DecoyRegistry) -> Bool {
        if registry.record(at: path) != nil { return true }
        return registry.mazeRoots.contains { path == $0 || path.hasPrefix($0 + "/") }
    }
}
