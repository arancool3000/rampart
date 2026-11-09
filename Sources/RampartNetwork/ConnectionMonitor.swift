import Foundation
import Darwin
import RampartShared

public struct NetworkConnection: Codable, Hashable, Sendable {
    public var pid: Int32
    public var processName: String
    public var processPath: String?
    public var proto: String          // "tcp" / "udp"
    public var localAddress: String
    public var localPort: UInt16
    public var remoteAddress: String
    public var remotePort: UInt16
    public var state: String?         // TCP state, e.g. "ESTABLISHED", "LISTEN"
    public var source: String         // "libproc" / "lsof"

    public init(pid: Int32, processName: String, processPath: String?, proto: String, localAddress: String, localPort: UInt16,
                remoteAddress: String, remotePort: UInt16, state: String?, source: String) {
        self.pid = pid; self.processName = processName; self.processPath = processPath; self.proto = proto
        self.localAddress = localAddress; self.localPort = localPort; self.remoteAddress = remoteAddress
        self.remotePort = remotePort; self.state = state; self.source = source
    }

    public var isListening: Bool { state == "LISTEN" }
    public var hasRemote: Bool { remotePort != 0 && !remoteAddress.isEmpty && remoteAddress != "0.0.0.0" && remoteAddress != "::" && remoteAddress != "*" }
}

/// Per-process socket snapshot. libproc (`proc_pidfdinfo` PROC_PIDFDSOCKETINFO) first; `lsof -F` fallback.
/// Non-root only sees the current user's processes.
public final class ConnectionMonitor: @unchecked Sendable {
    public init() {}

    /// - Parameter includeListeners: also return LISTEN / unconnected sockets.
    public func snapshot(includeListeners: Bool = false) -> [NetworkConnection] {
        var conns = libprocSnapshot()
        if conns.isEmpty { conns = lsofSnapshot() }
        return includeListeners ? conns : conns.filter(\.hasRemote)
    }

    // MARK: libproc

    static let tcpStates = ["CLOSED", "LISTEN", "SYN_SENT", "SYN_RECEIVED", "ESTABLISHED", "CLOSE_WAIT",
                            "FIN_WAIT_1", "CLOSING", "LAST_ACK", "FIN_WAIT_2", "TIME_WAIT"]

    public func libprocSnapshot() -> [NetworkConnection] {
        let n = proc_listallpids(nil, 0)
        guard n > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(n) + 64)
        let got = pids.withUnsafeMutableBytes { proc_listallpids($0.baseAddress, Int32($0.count)) }
        guard got > 0 else { return [] }
        var out: [NetworkConnection] = []
        for pid in pids.prefix(Int(got)) where pid > 0 {
            out += sockets(of: pid)
        }
        return out
    }

    public static func processPath(_ pid: Int32) -> String? {
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let r = proc_pidpath(pid, &buf, UInt32(buf.count))
        return r > 0 ? String(cString: buf) : nil
    }

    public static func processName(_ pid: Int32) -> String {
        var buf = [CChar](repeating: 0, count: 256)
        let r = proc_name(pid, &buf, UInt32(buf.count))
        if r > 0 { return String(cString: buf) }
        return processPath(pid).map { ($0 as NSString).lastPathComponent } ?? "pid \(pid)"
    }

    func sockets(of pid: Int32) -> [NetworkConnection] {
        let fdSize = MemoryLayout<proc_fdinfo>.stride
        let bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard bytes > 0 else { return [] }
        var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(bytes) / fdSize + 16)
        let used = fds.withUnsafeMutableBytes { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, $0.baseAddress, Int32($0.count)) }
        guard used > 0 else { return [] }
        var out: [NetworkConnection] = []
        var name: String?
        var path: String??
        for fd in fds.prefix(Int(used) / fdSize) where fd.proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) {
            var si = socket_fdinfo()
            let r = proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDSOCKETINFO, &si, Int32(MemoryLayout<socket_fdinfo>.size))
            guard r == Int32(MemoryLayout<socket_fdinfo>.size) else { continue }
            let family = si.psi.soi_family
            guard family == AF_INET || family == AF_INET6 else { continue }
            let kind = si.psi.soi_kind
            let ini: in_sockinfo
            var state: String?
            let proto: String
            if kind == Int32(SOCKINFO_TCP) {
                ini = si.psi.soi_proto.pri_tcp.tcpsi_ini
                let st = Int(si.psi.soi_proto.pri_tcp.tcpsi_state)
                state = st >= 0 && st < Self.tcpStates.count ? Self.tcpStates[st] : "STATE\(st)"
                proto = "tcp"
            } else if kind == Int32(SOCKINFO_IN) {
                ini = si.psi.soi_proto.pri_in
                proto = si.psi.soi_protocol == IPPROTO_UDP ? "udp" : "ip\(si.psi.soi_protocol)"
            } else { continue }
            let (la, ra) = Self.addresses(ini)
            if name == nil { name = Self.processName(pid) }
            if path == nil { path = .some(Self.processPath(pid)) }
            out.append(NetworkConnection(
                pid: pid, processName: name ?? "", processPath: path ?? nil, proto: proto,
                localAddress: la, localPort: UInt16(bigEndian: UInt16(truncatingIfNeeded: ini.insi_lport)),
                remoteAddress: ra, remotePort: UInt16(bigEndian: UInt16(truncatingIfNeeded: ini.insi_fport)),
                state: state, source: "libproc"))
        }
        return out
    }

    static func addresses(_ ini: in_sockinfo) -> (String, String) {
        var l = ini, f = ini
        if ini.insi_vflag & UInt8(INI_IPV4) != 0 {
            var la = l.insi_laddr.ina_46.i46a_addr4, fa = f.insi_faddr.ina_46.i46a_addr4
            return (withUnsafeBytes(of: &la) { DNSWire.addressString(Array($0)) },
                    withUnsafeBytes(of: &fa) { DNSWire.addressString(Array($0)) })
        }
        return (withUnsafeBytes(of: &l.insi_laddr.ina_6) { DNSWire.addressString(Array($0)) },
                withUnsafeBytes(of: &f.insi_faddr.ina_6) { DNSWire.addressString(Array($0)) })
    }

    // MARK: lsof fallback

    public func lsofSnapshot() -> [NetworkConnection] {
        let (_, out, _) = NetShell.run("/usr/sbin/lsof", ["-nP", "-iTCP", "-iUDP", "-FpcnPT"], timeout: 15)
        return Self.parseLsof(out)
    }

    /// Parses `lsof -F pcnPT` output.
    public static func parseLsof(_ text: String) -> [NetworkConnection] {
        var out: [NetworkConnection] = []
        var pid: Int32 = 0, cmd = "", proto = ""
        var pending: NetworkConnection?
        func flush() { if let p = pending { out.append(p) }; pending = nil }
        for raw in text.split(whereSeparator: \.isNewline) {
            guard let tag = raw.first else { continue }
            let v = String(raw.dropFirst())
            switch tag {
            case "p": flush(); pid = Int32(v) ?? 0; cmd = ""
            case "c": cmd = v
            case "f": flush()
            case "P": proto = v.lowercased()
            case "n":
                flush()
                let sides = v.components(separatedBy: "->")
                let (la, lp) = splitEndpoint(sides[0])
                let (ra, rp) = sides.count > 1 ? splitEndpoint(sides[1]) : ("", UInt16(0))
                pending = NetworkConnection(pid: pid, processName: cmd, processPath: nil, proto: proto,
                                            localAddress: la, localPort: lp, remoteAddress: ra, remotePort: rp,
                                            state: nil, source: "lsof")
            case "T":
                if v.hasPrefix("ST="), pending != nil { pending?.state = String(v.dropFirst(3)) }
            default: break
            }
        }
        flush()
        return out
    }

    static func splitEndpoint(_ s: String) -> (String, UInt16) {
        if s.hasPrefix("["), let close = s.firstIndex(of: "]") {
            let host = String(s[s.index(after: s.startIndex)..<close])
            let rest = s[s.index(after: close)...]
            return (host, UInt16(rest.dropFirst()) ?? 0)
        }
        guard let colon = s.lastIndex(of: ":") else { return (s, 0) }
        return (String(s[..<colon]), UInt16(s[s.index(after: colon)...]) ?? 0)
    }
}
