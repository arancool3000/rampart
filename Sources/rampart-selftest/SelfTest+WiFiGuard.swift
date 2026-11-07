import Foundation
import CoreWLAN
import RampartShared
import RampartNetwork

// Public Wi-Fi guard: fixture-only checks. No network access, never a real disassociate.
extension SelfTest {
    static func publicWiFiChecks() {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("com.rampart.test.pubwifi-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmp) }

        // Classification
        check(WiFiSecurityClass.classify(.none) == .open, "pubwifi classify open")
        check(WiFiSecurityClass.classify(.WEP) == .wep && WiFiSecurityClass.classify(.dynamicWEP) == .wep, "pubwifi classify wep")
        check(WiFiSecurityClass.classify(.wpaPersonal) == .wpa1, "pubwifi classify wpa1")
        check(WiFiSecurityClass.classify(.wpa2Personal) == .wpa2Personal, "pubwifi classify wpa2")
        check(WiFiSecurityClass.classify(.wpa3Enterprise) == .wpa3Enterprise, "pubwifi classify wpa3 ent")
        check(WiFiSecurityClass.classify(.OWE) == .enhancedOpen && !WiFiSecurityClass.enhancedOpen.isInsecure, "pubwifi OWE not insecure")
        check(WiFiSecurityClass.wpa1.isInsecure && !WiFiSecurityClass.wpa1.isDisconnectWorthy, "pubwifi wpa1 alerts but no disconnect")

        // Captive portal + DNS canary
        check(PublicWiFiGuard.captivePortal(status: 200, body: "<HTML><BODY>Success</BODY></HTML>") == false, "pubwifi no captive")
        check(PublicWiFiGuard.captivePortal(status: 302, body: "") == true, "pubwifi captive redirect")
        check(PublicWiFiGuard.captivePortal(status: nil, body: nil) == nil, "pubwifi captive inconclusive")
        check(PublicWiFiGuard.canaryVerdict(["one.one.one.one": ["1.1.1.1"], "dns.google": ["8.8.8.8"]]) == .ok, "pubwifi canary ok")
        check(PublicWiFiGuard.canaryVerdict(["one.one.one.one": ["10.0.0.9"], "dns.google": ["10.0.0.9"]]) == .hijacked, "pubwifi canary hijacked")
        check(PublicWiFiGuard.canaryVerdict(["one.one.one.one": ["10.0.0.9"], "dns.google": ["8.8.4.4"]]) == .ok, "pubwifi canary mixed is not hijack")
        check(PublicWiFiGuard.canaryVerdict(["one.one.one.one": []]) == .inconclusive, "pubwifi canary no answer")

        let gwArp = [WiFiGuard.ARPEntry(ip: "10.9.0.1", mac: "aa:bb:cc:00:00:01")]
        let settings = PublicWiFiSettings()

        // Open network, new → disconnect
        let open = PublicWiFiSnapshot(interface: "en0", ssid: "com.rampart.test.cafe", security: .open, gateway: "10.9.0.1", arp: gwArp,
                                      dnsServers: ["10.9.0.1"], captiveProbeStatus: 200, captiveProbeBody: "Success")
        let a1 = PublicWiFiGuard.assess(open, known: nil, settings: settings)
        check(a1.isNewNetwork && a1.decision.isDisconnect && a1.severity == .medium, "pubwifi open new → disconnect")
        check(a1.detection?.name == "Insecure public Wi-Fi", "pubwifi open detection")
        check(a1.summary.contains("Open"), "pubwifi summary")

        // Setting off → alert only
        var off = settings; off.disconnectInsecureWiFi = false
        check(PublicWiFiGuard.assess(open, known: nil, settings: off).decision == .alertOnly, "pubwifi setting off → alert only")

        // Trusted → never disconnect, even under attack
        let trusted = KnownWiFiNetwork(key: a1.networkKey, ssid: open.ssid, security: .open, gatewayMAC: "aa:bb:cc:00:00:01", trusted: true)
        var spoofArp = gwArp; spoofArp.append(WiFiGuard.ARPEntry(ip: "10.9.0.66", mac: "aa:bb:cc:00:00:01"))
        var spoof = open; spoof.arp = spoofArp
        let aT = PublicWiFiGuard.assess(spoof, known: trusted, settings: settings)
        check(aT.arpSpoofing && aT.decision == .alertOnly, "pubwifi trusted never disconnected")

        // WPA2 clean → none, no detection
        var wpa2 = open; wpa2.security = .wpa2Personal; wpa2.dnsCanaryAnswers = ["one.one.one.one": ["1.1.1.1"]]
        let aW = PublicWiFiGuard.assess(wpa2, known: nil, settings: settings)
        check(aW.decision == .none && aW.detection == nil, "pubwifi wpa2 clean")

        // WPA2 + DNS hijack → disconnect; but not when behind a captive portal
        var hij = wpa2; hij.dnsCanaryAnswers = ["one.one.one.one": ["10.9.0.1"], "dns.google": ["10.9.0.1"]]
        let aH = PublicWiFiGuard.assess(hij, known: nil, settings: settings)
        check(aH.dnsHijack && aH.decision.isDisconnect && aH.severity == .high, "pubwifi dns hijack → disconnect")
        var hijCap = hij; hijCap.captiveProbeStatus = 302
        check(!PublicWiFiGuard.assess(hijCap, known: nil, settings: settings).dnsHijack, "pubwifi captive DNS not hijack")
        var noAttack = settings; noAttack.disconnectOnAttack = false
        check(PublicWiFiGuard.assess(hij, known: nil, settings: noAttack).decision == .alertOnly, "pubwifi attack disconnect toggle")

        // Gateway MAC change within session → spoofing
        var changed = wpa2; changed.arp = [WiFiGuard.ARPEntry(ip: "10.9.0.1", mac: "de:ad:00:00:00:02")]
        let aM = PublicWiFiGuard.assess(changed, known: nil, sessionGatewayMAC: "aa:bb:cc:00:00:01", settings: settings)
        check(aM.gatewayMACChanged && aM.decision.isDisconnect, "pubwifi gateway MAC change → disconnect")
        // Same 10.x gateway IP on a different (non-SSID-keyed) network must not count as a change
        let otherNet = KnownWiFiNetwork(key: "gw:aa:bb:cc:00:00:01", ssid: nil, security: .wpa2Personal, gatewayMAC: "aa:bb:cc:00:00:01")
        var noSSID = changed; noSSID.ssid = nil
        check(!PublicWiFiGuard.assess(noSSID, known: otherNet, settings: settings).gatewayMACChanged, "pubwifi no cross-network MAC FP")

        // Risky gateway port
        var ports = wpa2; ports.gatewayPorts = [23: true, 80: true, 443: false]
        check(PublicWiFiGuard.assess(ports, known: nil, settings: settings).gatewayRiskyPorts == [23], "pubwifi risky gateway port")

        // Store
        let store = KnownWiFiNetworkStore(url: tmp.appendingPathComponent("known.json"))
        store.upsert(KnownWiFiNetwork(key: "ssid:home|wpa2Personal", ssid: "home", security: .wpa2Personal, gatewayMAC: nil))
        store.setTrusted("ssid:home|wpa2Personal", true)
        let reloaded = KnownWiFiNetworkStore(url: tmp.appendingPathComponent("known.json"))
        check(reloaded.network("ssid:home|wpa2Personal")?.trusted == true, "pubwifi store persists trust")

        // Guard flow with fake disassociator (never real)
        let fake = DryRunDisassociator()
        let g = PublicWiFiGuard(store: KnownWiFiNetworkStore(url: tmp.appendingPathComponent("g.json")), disassociator: fake)
        let r1 = g.handle(open, known: nil)
        check(r1.decision.isDisconnect && g.hasPendingDisconnect, "pubwifi guard schedules disconnect")
        g.stayConnected()
        check(!g.hasPendingDisconnect && fake.calls.isEmpty, "pubwifi stay connected cancels")
        let r2 = g.handle(open, known: g.store.network(r1.networkKey))
        check(r2.decision == .alertOnly, "pubwifi stay connected remembered")
        let g2 = PublicWiFiGuard(store: KnownWiFiNetworkStore(url: tmp.appendingPathComponent("g2.json")), disassociator: fake)
        _ = g2.handle(open, known: nil)
        g2.firePendingNow()
        check(fake.calls == ["en0"], "pubwifi fires fake disassociate after grace")
        let g3 = PublicWiFiGuard(store: KnownWiFiNetworkStore(url: tmp.appendingPathComponent("g3.json")), disassociator: fake)
        let r3 = g3.handle(open, known: nil)
        g3.store.setTrusted(r3.networkKey, true)
        g3.firePendingNow()
        check(fake.calls.count == 1, "pubwifi trusted at fire time is skipped")
        check(!CoreWLANDisassociator().disassociate(interface: "en0"), "pubwifi real disassociator refuses by default")
    }
}
