import Foundation
import Security

/// hx8: who may sit behind a RamPart daemon socket. Pure policies (unit-tested by rampart-selftest) plus the
/// OS-level checks shared by the app, the CLI and the secure browser.
///
/// - Root socket (`IPC.socketPath`): a real socket owned by root, and the peer must be uid 0.
/// - User socket: owned by us (or root), in a folder only we can write, peer running as us; the caller decides
///   how strictly the peer's code signature is checked (`signatureOK`).
/// Honest limit: with ad-hoc signing anyone can produce a binary with RamPart's identifier; same-user malware that
/// can replace the helper can still impersonate it. These checks stop other users and socket squatting.
public enum DaemonPeerPolicy {
    public static func socketFileProblem(isSymlink: Bool, isSocket: Bool, ownerUID: uid_t, rootSocket: Bool,
                                         myUID: uid_t, parentOwnerUID: uid_t, parentMode: mode_t) -> String? {
        if isSymlink { return "socket path is a symbolic link" }
        if !isSocket { return "socket path is not a socket" }
        if rootSocket { return ownerUID == 0 ? nil : "system socket is not owned by root" }
        if ownerUID != myUID && ownerUID != 0 { return "socket is owned by another user" }
        if parentOwnerUID != myUID && parentOwnerUID != 0 { return "socket folder is owned by another user" }
        if parentMode & (S_IWGRP | S_IWOTH) != 0 { return "socket folder is writable by other users" }
        return nil
    }

    public static func socketFileProblem(path: String) -> String? {
        var st = stat()
        guard lstat(path, &st) == 0 else { return "socket path can't be read" }
        var pst = stat()
        let parent = (path as NSString).deletingLastPathComponent
        guard stat(parent, &pst) == 0 else { return "socket folder can't be read" }
        return socketFileProblem(isSymlink: (st.st_mode & S_IFMT) == S_IFLNK, isSocket: (st.st_mode & S_IFMT) == S_IFSOCK,
                                 ownerUID: st.st_uid, rootSocket: path == IPC.socketPath, myUID: getuid(),
                                 parentOwnerUID: pst.st_uid, parentMode: pst.st_mode)
    }

    public static func peerProblem(peerUID: uid_t, myUID: uid_t, rootSocket: Bool, signatureOK: () -> Bool) -> String? {
        if peerUID == 0 { return nil }                  // root daemon; a root attacker is out of scope
        if rootSocket { return "system socket peer is not root" }
        if peerUID != myUID { return "peer runs as another user" }
        return signatureOK() ? nil : "peer is not the signed \(Product.name) helper"
    }

    /// Peer pid of a connected Unix socket (LOCAL_PEERPID).
    public static func peerPID(fd: Int32) -> pid_t? {
        var pid: pid_t = 0
        var len = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &len) == 0, pid > 0 else { return nil }
        return pid
    }

    /// wms-fa: which daemon signing identifiers a client accepts. The packaged identifier always. The development
    /// names (`swift build` output is linker-signed "rampartd" / "rampartd-<hash>") only when the client is itself a
    /// development build: a packaged CLI or nmh (`app.rampart.*`) used to accept any same-user binary that an attacker
    /// had ad-hoc signed as "rampartd-x" squatting the user socket.
    public static func daemonIdentifierAcceptable(_ ident: String, selfIdentifier: String?, peerHardened: Bool) -> Bool {
        let packagedClient = selfIdentifier?.hasPrefix(Product.bundlePrefix + ".") == true
        if ident == Product.bundlePrefix + ".daemon" { return !packagedClient || peerHardened }
        return !packagedClient && (ident == "rampartd" || ident.hasPrefix("rampartd-"))
    }

    /// This process's own code-signing identifier (nil when unsigned or unreadable).
    public static let selfIdentifier: String? = {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
        var st: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &st) == errSecSuccess, let st else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(st, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let d = info as? [String: Any] else { return nil }
        return d[kSecCodeInfoIdentifier as String] as? String
    }()

    /// Default signature check for clients that are not inside the app bundle (CLI, browser, nmh): the peer's code is
    /// valid and signed with RamPart's daemon identifier (hardened runtime when this client is a packaged build).
    /// Weak with ad-hoc signing (see the honest limit above).
    public static func peerLooksLikeDaemon(pid: pid_t) -> Bool {
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary, [], &code) == errSecSuccess,
              let code, SecCodeCheckValidity(code, [], nil) == errSecSuccess else { return false }
        var st: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &st) == errSecSuccess, let st else { return false }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(st, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let d = info as? [String: Any], let ident = d[kSecCodeInfoIdentifier as String] as? String else { return false }
        let flags = (d[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        return daemonIdentifierAcceptable(ident, selfIdentifier: selfIdentifier, peerHardened: flags & 0x10000 != 0)
    }

    /// Full check of a connected socket for CLI / browser clients. nil = trusted.
    public static func connectedPeerProblem(fd: Int32, path: String) -> String? {
        if let p = socketFileProblem(path: path) { return p }
        var uid: uid_t = 0, gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0 else { return "can't read peer credentials" }
        return peerProblem(peerUID: uid, myUID: getuid(), rootSocket: path == IPC.socketPath) {
            guard let pid = peerPID(fd: fd) else { return false }
            return peerLooksLikeDaemon(pid: pid)
        }
    }
}
