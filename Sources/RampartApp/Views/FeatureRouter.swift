import SwiftUI
import RampartShared

/// Tools section router: one line per feature. Each owner's root view lives in Features/<Name>/.
/// Features without a screen yet show a calm placeholder. Rendered lazily: nothing is created until selected.
enum FeatureRouter {
    @MainActor @ViewBuilder
    static func view(for item: SidebarItem) -> some View {
        switch item {
        case .aiAssistant: AIAssistantView()
        case .remoteAccess: RemoteAccessView()
        case .passwords: PasswordsView()
        case .refresh: RefreshDestinationView(item: .refreshSmart)
        case .emergency: EmergencyView()
        case .catAndMouse: CatAndMouseView()
        case .downloadGate: DownloadGateView()
        case .mediaGuard: MediaGuardView()
        case .appFirewall: AppFirewallView()
        case .privacyFilters: PrivacyFiltersView()
        case .vpn: VPNView()
        case .authenticator: AuthenticatorView()
        case .passwordChecker: PasswordCheckerView()
        case .networkScan: NetworkScanView()
        // Not built yet: replace the placeholder with the owner's view when it lands.
        case .scamCheck: ScamCheckView()
        default: FeaturePlaceholderView(item: item)
        }
    }
}

/// Feature services that run in the user session. Kept here so the core app files don't import feature modules.
enum AppFeatures {
    @MainActor static func startBackgroundServices() { PasteGuardHost.shared.start(); ScamAIWiring.install(); PublicWiFiHost.shared.start(); VPNAutoConnector.shared.start(); FDAAutoPrompt.runIfNeeded(); DesktopMode.shared.start(); BotController.shared.start(); BreachWatch.shared.start() }
    @MainActor static func explain(_ d: Detection) {
        AIChatModel.shared.explain(d)
        AppModel.shared.selection = .aiAssistant
    }
}
