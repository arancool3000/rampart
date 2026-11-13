import Foundation

/// Pre-checks attacker-supplied property lists before CoreFoundation parses them. CF's XML and binary plist
/// parsers recurse once per nesting level, so a few hundred KB of `<array><array>…` (or a binary plist whose
/// arrays point at each other in a chain) overflows a 512 KB scan-thread stack and crashes the scanner.
/// We only ever need shallow plists (entitlements, kMDItemWhereFroms), so anything deeper is refused.
public enum PlistGuard {
    public static let maxDepth = 48

    /// Parses `data` only if it is at most `maxBytes` long and nested at most `maxDepth` levels.
    public static func propertyList(_ data: Data, maxBytes: Int = 1 << 20) -> Any? {
        guard !data.isEmpty, data.count <= maxBytes, isShallow(data) else { return nil }
        return try? PropertyListSerialization.propertyList(from: data, format: nil)
    }

    public static func isShallow(_ data: Data, maxDepth: Int = maxDepth) -> Bool {
        let b = [UInt8](data)
        if b.count >= 8, Array(b[0..<6]) == Array("bplist".utf8) { return binaryShallow(b, maxDepth: maxDepth) }
        return textShallow(b, maxDepth: maxDepth)
    }

    /// XML / OpenStep text: container tags or brackets may not nest deeper than `maxDepth`. No DTD entities.
    static func textShallow(_ b: [UInt8], maxDepth: Int) -> Bool {
        var depth = 0, i = 0
        let n = b.count
        // XML counts tags only (string values may contain brackets); OpenStep counts brackets.
        let xml = b.first(where: { $0 != 0x20 && $0 != 0x09 && $0 != 0x0A && $0 != 0x0D && $0 != 0xEF && $0 != 0xBB && $0 != 0xBF }) == UInt8(ascii: "<")
        func at(_ s: String, _ k: Int) -> Bool {
            let u = Array(s.utf8); return k + u.count <= n && Array(b[k..<(k + u.count)]) == u
        }
        while i < n {
            let c = b[i]
            if c == UInt8(ascii: "<") {
                if at("<!ENTITY", i) { return false }
                if at("<array", i) || at("<dict", i) {
                    // Self-closing <array/> does not nest.
                    var j = i + 1
                    while j < n && b[j] != UInt8(ascii: ">") { j += 1 }
                    if !(j > 0 && j < n && b[j - 1] == UInt8(ascii: "/")) { depth += 1 }
                    i = j; continue
                }
                if at("</array", i) || at("</dict", i) { depth -= 1 }
            } else if !xml && (c == UInt8(ascii: "(") || c == UInt8(ascii: "{")) {
                depth += 1          // OpenStep plists
            } else if !xml && (c == UInt8(ascii: ")") || c == UInt8(ascii: "}")) {
                depth -= 1
            }
            if depth > maxDepth { return false }
            i += 1
        }
        return true
    }

    /// Binary plist: walks the object graph from the top object without recursion and measures the longest
    /// container chain. Malformed tables, cycles and absurd object counts are refused.
    static func binaryShallow(_ b: [UInt8], maxDepth: Int) -> Bool {
        let n = b.count
        guard n >= 8 + 32 else { return false }
        let t = n - 32
        let offSize = Int(b[t + 6]), refSize = Int(b[t + 7])
        func be(_ o: Int, _ size: Int) -> Int? {
            guard size >= 1, size <= 8, o >= 0, o + size <= n else { return nil }
            var v: UInt64 = 0
            for k in 0..<size { v = v << 8 | UInt64(b[o + k]) }
            return v > UInt64(Int.max) ? nil : Int(v)
        }
        guard let count = be(t + 8, 8), let top = be(t + 16, 8), let table = be(t + 24, 8),
              count > 0, count <= 1 << 20, top < count, table < n,
              count.multipliedReportingOverflow(by: offSize).partialValue <= n - table else { return false }
        func offset(_ obj: Int) -> Int? { obj < count ? be(table + obj * offSize, offSize) : nil }
        func children(_ obj: Int) -> [Int]? {
            guard let o = offset(obj), o < n else { return nil }
            let marker = b[o], kind = marker >> 4
            guard kind == 0xA || kind == 0xB || kind == 0xC || kind == 0xD else { return [] }
            var c = Int(marker & 0x0F), p = o + 1
            if c == 0x0F {
                guard p < n, b[p] >> 4 == 0x1 else { return nil }
                let sz = 1 << Int(b[p] & 0x0F)
                guard let v = be(p + 1, sz) else { return nil }
                c = v; p += 1 + sz
            }
            let refs = kind == 0xD ? c.multipliedReportingOverflow(by: 2).partialValue : c
            guard refs >= 0, refs <= count * 2, p + refs * refSize <= n else { return nil }
            var out: [Int] = []
            out.reserveCapacity(refs)
            for k in 0..<refs { guard let r = be(p + k * refSize, refSize), r < count else { return nil }; out.append(r) }
            return out
        }
        // Iterative DFS computing the longest path (memoised); grey nodes on the stack detect cycles.
        var height = [Int](repeating: -1, count: count)     // -1 unvisited, -2 in progress
        var stack: [(obj: Int, kids: [Int], next: Int)] = []
        var work = 0
        guard let k0 = children(top) else { return false }
        height[top] = -2; stack.append((top, k0, 0))
        while !stack.isEmpty {
            work += 1
            if work > 4 << 20 { return false }
            if stack.count > maxDepth { return false }
            let idx = stack.count - 1
            if stack[idx].next < stack[idx].kids.count {
                let child = stack[idx].kids[stack[idx].next]
                stack[idx].next += 1
                if height[child] == -2 { return false }            // cycle
                if height[child] >= 0 { continue }
                guard let kc = children(child) else { return false }
                height[child] = -2
                stack.append((child, kc, 0))
            } else {
                let done = stack.removeLast()
                var h = 0
                for k in done.kids where height[k] >= 0 { h = max(h, height[k] + 1) }
                if h > maxDepth { return false }
                height[done.obj] = h
            }
        }
        return true
    }
}
