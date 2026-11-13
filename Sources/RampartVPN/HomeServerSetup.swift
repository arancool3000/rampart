import Foundation

/// "Set up my home server": generates both key pairs and a preshared key, returns the client config (imported
/// straight into RamPart, its private key going to the Keychain) and a ready server config with the exact install
/// commands for Raspberry Pi OS and for macOS with Homebrew's wireguard-tools. RamPart never runs these commands.
public struct HomeServerKit: Codable, Equatable, Sendable {
    public var endpointHost: String
    public var port: UInt16
    public var serverPublicKey: String
    public var clientPublicKey: String
    /// Server wg0.conf for Raspberry Pi OS / Linux (iptables NAT). Contains the server's private key.
    public var raspberryPiConfig: String
    /// Server wg0.conf for macOS (pf NAT). Contains the server's private key.
    public var macConfig: String
    public var raspberryPiCommands: String
    public var macCommands: String
    public var routerSteps: [String]
    public var notes: [String]
}

public enum HomeServerSetup {
    public static let defaultPort: UInt16 = 51820
    public static let subnet4 = "10.66.66"
    public static let subnet6 = "fd66:66:66::"

    public struct Result {
        public var clientConfig: WGQuickConfig
        public var kit: HomeServerKit
    }

    public enum SetupError: Error, CustomStringConvertible {
        case badHost, badPort
        public var description: String {
            switch self {
            case .badHost: return "Enter your home server's address: a hostname such as myhome.duckdns.org (or imac.local for testing at home) or an IP address."
            case .badPort: return "The port must be between 1 and 65535 (WireGuard's usual port is 51820)."
            }
        }
    }

    public static func generate(endpointHost: String, port: UInt16 = defaultPort, dns: [String]? = nil,
                                privateKeys: (server: [UInt8], client: [UInt8], psk: [UInt8])? = nil) throws -> Result {
        let host = endpointHost.trimmingCharacters(in: .whitespaces)
        guard IPPrefix.strictLiteral(host) != nil || WGQuickConfig.isHostname(host) else { throw SetupError.badHost }
        guard port > 0 else { throw SetupError.badPort }
        let serverPriv = privateKeys?.server ?? WGCrypto.generatePrivateKey()
        let clientPriv = privateKeys?.client ?? WGCrypto.generatePrivateKey()
        let psk = privateKeys?.psk ?? WGCrypto.randomBytes(32)
        let serverPub = try WGCrypto.publicKey(serverPriv)
        let clientPub = try WGCrypto.publicKey(clientPriv)

        var client = WGQuickConfig(privateKey: clientPriv, peerPublicKey: serverPub, endpointHost: host, endpointPort: port)
        client.addresses = ["\(subnet4).2/32", "\(subnet6)2/128"]
        client.dnsServers = dns ?? ["1.1.1.1", "2606:4700:4700::1111"]
        client.presharedKey = psk
        client.allowedIPs = ["0.0.0.0/0", "::/0"]
        client.persistentKeepalive = 25

        let peerBlock = """
        [Peer]
        # This Mac (RamPart VPN)
        PublicKey = \(WGKey.base64(clientPub))
        PresharedKey = \(WGKey.base64(psk))
        AllowedIPs = \(subnet4).2/32, \(subnet6)2/128
        """
        let piConfig = """
        # RamPart VPN home server (Raspberry Pi OS / Linux). Keep this file private: it holds the server's private key.
        [Interface]
        Address = \(subnet4).1/24, \(subnet6)1/64
        ListenPort = \(port)
        PrivateKey = \(WGKey.base64(serverPriv))
        # Forward the Mac's traffic to the internet through the Pi's default network interface.
        PostUp = WAN=$(ip route show default | awk '/default/ {print $5; exit}'); iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -s \(subnet4).0/24 -o $WAN -j MASQUERADE; ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -A FORWARD -o %i -j ACCEPT; ip6tables -t nat -A POSTROUTING -s \(subnet6)/64 -o $WAN -j MASQUERADE
        PostDown = WAN=$(ip route show default | awk '/default/ {print $5; exit}'); iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -s \(subnet4).0/24 -o $WAN -j MASQUERADE; ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -D FORWARD -o %i -j ACCEPT; ip6tables -t nat -D POSTROUTING -s \(subnet6)/64 -o $WAN -j MASQUERADE

        \(peerBlock)

        """
        let macConfig = """
        # RamPart VPN home server (macOS, Homebrew wireguard-tools). Keep this file private: it holds the server's private key.
        [Interface]
        Address = \(subnet4).1/24, \(subnet6)1/64
        ListenPort = \(port)
        PrivateKey = \(WGKey.base64(serverPriv))
        # Turn on forwarding and NAT the Mac's traffic out of this computer's default interface (pf anchor under com.apple).
        PostUp = sysctl -w net.inet.ip.forwarding=1 net.inet6.ip6.forwarding=1; WAN=$(route -n get default | awk '/interface:/ {print $2}'); printf 'nat on %s inet from \(subnet4).0/24 to any -> (%s)\\nnat on %s inet6 from \(subnet6)/64 to any -> (%s)\\n' $WAN $WAN $WAN $WAN | pfctl -a com.apple/rampart-vpn-server -f -; pfctl -E
        PostDown = pfctl -a com.apple/rampart-vpn-server -F all; sysctl -w net.inet.ip.forwarding=0 net.inet6.ip6.forwarding=0

        \(peerBlock)

        """
        let piCommands = """
        # On the Raspberry Pi (Raspberry Pi OS), in Terminal or over SSH:
        sudo apt update
        sudo apt install -y wireguard iptables
        sudo install -d -m 700 /etc/wireguard
        sudo nano /etc/wireguard/wg0.conf        # paste the Raspberry Pi server config, then save (Ctrl+O, Enter, Ctrl+X)
        sudo chmod 600 /etc/wireguard/wg0.conf
        printf 'net.ipv4.ip_forward=1\\nnet.ipv6.conf.all.forwarding=1\\n' | sudo tee /etc/sysctl.d/99-rampart-vpn.conf
        sudo sysctl --system
        sudo systemctl enable --now wg-quick@wg0
        sudo wg show                             # "latest handshake" appears once this Mac connects
        """
        let macCommands = """
        # On the home Mac (macOS with Homebrew: https://brew.sh), in Terminal:
        brew install wireguard-tools
        sudo mkdir -p "$(brew --prefix)/etc/wireguard"
        sudo nano "$(brew --prefix)/etc/wireguard/wg0.conf"    # paste the macOS server config, then save
        sudo chmod 600 "$(brew --prefix)/etc/wireguard/wg0.conf"
        sudo wg-quick up wg0
        sudo wg show                                           # "latest handshake" appears once this Mac connects
        # To stop it: sudo wg-quick down wg0
        # Keep the home Mac awake: System Settings > Energy > Prevent automatic sleeping when the display is off.
        """
        let local = host.hasSuffix(".local") || (IPPrefix.parseAddress(host).map(isPrivate) ?? false)
        var notes = [
            "Your traffic goes through your own home server; RamPart doesn't run VPN servers and never sees your traffic.",
            "The server config holds the server's private key. RamPart shows it once and doesn't keep it; this Mac's own private key stays in the Keychain.",
            "RamPart never runs these commands for you.",
        ]
        if local {
            notes.insert("\(host) only works while this Mac is on your home network. To use the VPN on public Wi-Fi, use your home's public address or a dynamic DNS name (for example from your router or duckdns.org) and forward the port on your router.", at: 0)
        }
        let kit = HomeServerKit(
            endpointHost: host, port: port, serverPublicKey: WGKey.base64(serverPub), clientPublicKey: WGKey.base64(clientPub),
            raspberryPiConfig: piConfig, macConfig: macConfig, raspberryPiCommands: piCommands, macCommands: macCommands,
            routerSteps: [
                "Give the server a fixed address on your home network (a DHCP reservation in your router).",
                "Forward UDP port \(port) on your router to that address.",
                "If your home's public address changes, set up dynamic DNS and use that name as the server address here.",
            ],
            notes: notes)
        return Result(clientConfig: client, kit: kit)
    }

    static func isPrivate(_ a: [UInt8]) -> Bool {
        if a.count == 4 { return a[0] == 10 || (a[0] == 172 && (16...31).contains(a[1])) || (a[0] == 192 && a[1] == 168) || (a[0] == 169 && a[1] == 254) }
        return a.count == 16 && ((a[0] & 0xfe) == 0xfc || (a[0] == 0xfe && (a[1] & 0xc0) == 0x80))
    }
}
