import Foundation
import Darwin

/// Packet I/O for the tunnel side. `UTunDevice` in the root daemon; in-memory in tests.
public protocol TunnelPacketIO: AnyObject {
    var name: String { get }
    /// Starts delivering packets read from the interface.
    func start(onPacket: @escaping ([UInt8]) -> Void)
    func write(_ packet: [UInt8])
    func close()
}

/// Datagram I/O for the encrypted side.
public protocol TunnelDatagramIO: AnyObject {
    var localPort: UInt16 { get }
    func start(onDatagram: @escaping ([UInt8], WGEndpoint) -> Void)
    func send(_ bytes: [UInt8], to: WGEndpoint)
    func close()
}

public enum TunnelIOError: Error, CustomStringConvertible {
    case refused(String), system(String, Int32)
    public var description: String {
        switch self {
        case .refused(let s): return s
        case .system(let what, let e): return "\(what) failed: \(String(cString: strerror(e)))"
        }
    }
}

/// A utun interface from the `com.apple.net.utun_control` kernel control (no NetworkExtension needed, root only).
/// Each packet carries a 4-byte protocol family header (AF_INET / AF_INET6, network byte order).
public final class UTunDevice: TunnelPacketIO {
    public static let controlName = "com.apple.net.utun_control"
    static let ctliocginfo: UInt = 0xC064_4E03          // _IOWR('N', 3, struct ctl_info)
    static let utunOptIfname: Int32 = 2
    static let sysprotoControl: Int32 = 2
    static let afSysControl: UInt16 = 2

    public let fd: Int32
    public let name: String
    private var source: DispatchSourceRead?
    private let queue: DispatchQueue

    /// Refuses outside the installed root daemon (and always with RAMPART_NO_PRIVILEGED_TOOLS=1).
    public init(queue: DispatchQueue) throws {
        guard LiveVPNRunner.allowed else { throw TunnelIOError.refused("creating a utun interface needs the installed system service (root)") }
        self.queue = queue
        let fd = socket(PF_SYSTEM, SOCK_DGRAM, Self.sysprotoControl)
        guard fd >= 0 else { throw TunnelIOError.system("socket(PF_SYSTEM)", errno) }
        var info = ctl_info()
        withUnsafeMutableBytes(of: &info.ctl_name) { buf in
            let n = Array(Self.controlName.utf8)
            for i in 0..<min(n.count, buf.count - 1) { buf[i] = n[i] }
        }
        guard ioctl(fd, Self.ctliocginfo, &info) == 0 else { let e = errno; Darwin.close(fd); throw TunnelIOError.system("CTLIOCGINFO", e) }
        var addr = sockaddr_ctl()
        addr.sc_len = UInt8(MemoryLayout<sockaddr_ctl>.size)
        addr.sc_family = UInt8(AF_SYSTEM)
        addr.ss_sysaddr = Self.afSysControl
        addr.sc_id = info.ctl_id
        addr.sc_unit = 0   // let the kernel choose utunN
        let rc = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_ctl>.size)) } }
        guard rc == 0 else { let e = errno; Darwin.close(fd); throw TunnelIOError.system("connect(utun)", e) }
        var nameBuf = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        var len = socklen_t(nameBuf.count)
        guard getsockopt(fd, Self.sysprotoControl, Self.utunOptIfname, &nameBuf, &len) == 0 else { let e = errno; Darwin.close(fd); throw TunnelIOError.system("UTUN_OPT_IFNAME", e) }
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        self.fd = fd
        name = String(cString: nameBuf)
    }

    public func start(onPacket: @escaping ([UInt8]) -> Void) {
        let s = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        var buf = [UInt8](repeating: 0, count: 65536)
        s.setEventHandler { [fd] in
            while true {
                let n = read(fd, &buf, buf.count)
                if n <= 4 { break }
                onPacket(Array(buf[4..<n]))
            }
        }
        s.resume(); source = s
    }

    public func write(_ packet: [UInt8]) {
        guard let v = packet.first.map({ $0 >> 4 }) else { return }
        let af: UInt32 = v == 6 ? UInt32(AF_INET6) : UInt32(AF_INET)
        let hdr = withUnsafeBytes(of: af.bigEndian) { Array($0) }
        let out = hdr + packet
        _ = out.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
    }

    public func close() { source?.cancel(); source = nil; Darwin.close(fd) }
}

/// The WireGuard UDP socket, optionally pinned to the physical interface (IP_BOUND_IF) so it never loops into the tunnel.
public final class UDPSocketIO: TunnelDatagramIO {
    public let fd: Int32
    public let family: Int32
    public private(set) var localPort: UInt16 = 0
    private var source: DispatchSourceRead?
    private let queue: DispatchQueue

    public init(ipv6: Bool, port: UInt16 = 0, boundInterface: String? = nil, queue: DispatchQueue) throws {
        self.queue = queue
        family = ipv6 ? AF_INET6 : AF_INET
        let fd = socket(family, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { throw TunnelIOError.system("socket(UDP)", errno) }
        self.fd = fd
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        if let ifn = boundInterface, case let idx = if_nametoindex(ifn), idx != 0 {
            var i = UInt32(idx)
            if ipv6 { _ = setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &i, socklen_t(4)) }
            else { _ = setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &i, socklen_t(4)) }
        }
        let rc: Int32
        if ipv6 {
            var a = sockaddr_in6(); a.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size); a.sin6_family = sa_family_t(AF_INET6); a.sin6_port = port.bigEndian
            a.sin6_addr = in6addr_any
            rc = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
        } else {
            var a = sockaddr_in(); a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); a.sin_family = sa_family_t(AF_INET); a.sin_port = port.bigEndian
            rc = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        }
        guard rc == 0 else { let e = errno; Darwin.close(fd); throw TunnelIOError.system("bind(UDP)", e) }
        var ss = sockaddr_storage(); var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
        _ = withUnsafeMutablePointer(to: &ss) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        localPort = Self.endpoint(from: ss)?.port ?? port
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
    }

    static func endpoint(from ss: sockaddr_storage) -> WGEndpoint? {
        var ss = ss
        if Int32(ss.ss_family) == AF_INET {
            return withUnsafePointer(to: &ss) { $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { p in
                var a = p.pointee.sin_addr
                return WGEndpoint(host: IPPrefix.format(withUnsafeBytes(of: &a) { Array($0) }), port: UInt16(bigEndian: p.pointee.sin_port))
            } }
        }
        if Int32(ss.ss_family) == AF_INET6 {
            return withUnsafePointer(to: &ss) { $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { p in
                var a = p.pointee.sin6_addr
                return WGEndpoint(host: IPPrefix.format(withUnsafeBytes(of: &a) { Array($0) }), port: UInt16(bigEndian: p.pointee.sin6_port))
            } }
        }
        return nil
    }

    public func start(onDatagram: @escaping ([UInt8], WGEndpoint) -> Void) {
        let s = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        var buf = [UInt8](repeating: 0, count: 65536)
        s.setEventHandler { [fd] in
            while true {
                var ss = sockaddr_storage(); var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
                let n = withUnsafeMutablePointer(to: &ss) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &buf, buf.count, 0, $0, &len) } }
                if n <= 0 { break }
                if let ep = UDPSocketIO.endpoint(from: ss) { onDatagram(Array(buf[0..<n]), ep) }
            }
        }
        s.resume(); source = s
    }

    public func send(_ bytes: [UInt8], to ep: WGEndpoint) {
        guard let a = IPPrefix.parseAddress(ep.host) else { return }
        if a.count == 4, family == AF_INET {
            var sa = sockaddr_in(); sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); sa.sin_family = sa_family_t(AF_INET); sa.sin_port = ep.port.bigEndian
            withUnsafeMutableBytes(of: &sa.sin_addr) { $0.copyBytes(from: a) }
            _ = withUnsafePointer(to: &sa) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, bytes, bytes.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        } else if a.count == 16, family == AF_INET6 {
            var sa = sockaddr_in6(); sa.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size); sa.sin6_family = sa_family_t(AF_INET6); sa.sin6_port = ep.port.bigEndian
            withUnsafeMutableBytes(of: &sa.sin6_addr) { $0.copyBytes(from: a) }
            _ = withUnsafePointer(to: &sa) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, bytes, bytes.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
        }
    }

    public func close() { source?.cancel(); source = nil; Darwin.close(fd) }
}

/// Resolves the server's host name (also .local via mDNS). IPv4 preferred.
public enum EndpointResolver {
    public static func resolve(_ host: String, port: UInt16) -> WGEndpoint? {
        if IPPrefix.parseAddress(host) != nil { return WGEndpoint(host: host, port: port) }
        var hints = addrinfo(); hints.ai_socktype = SOCK_DGRAM; hints.ai_family = AF_UNSPEC
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &res) == 0, let first = res else { return nil }
        defer { freeaddrinfo(res) }
        var v4: WGEndpoint?, v6: WGEndpoint?
        var p: UnsafeMutablePointer<addrinfo>? = first
        while let ai = p {
            var ss = sockaddr_storage()
            memcpy(&ss, ai.pointee.ai_addr, Int(ai.pointee.ai_addrlen))
            if let ep = UDPSocketIO.endpoint(from: ss) {
                if ai.pointee.ai_family == AF_INET, v4 == nil { v4 = ep }
                if ai.pointee.ai_family == AF_INET6, v6 == nil, !ep.host.lowercased().hasPrefix("fe80") { v6 = ep }
            }
            p = ai.pointee.ai_next
        }
        return v4 ?? v6
    }
}

/// In-memory packet pipe for tests and dry runs.
public final class MemoryPacketIO: TunnelPacketIO {
    public let name: String
    public private(set) var written: [[UInt8]] = []
    private var handler: (([UInt8]) -> Void)?
    public init(name: String = "utun-test") { self.name = name }
    public func start(onPacket: @escaping ([UInt8]) -> Void) { handler = onPacket }
    public func write(_ packet: [UInt8]) { written.append(packet) }
    /// Simulates an app sending a packet into the tunnel interface.
    public func inject(_ p: [UInt8]) { handler?(p) }
    public func close() { handler = nil }
}
