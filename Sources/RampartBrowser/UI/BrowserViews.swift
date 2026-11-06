import SwiftUI
import AppKit
import WebKit

// MARK: - Window content

struct BrowserWindowView: View {
    @Bindable var model: BrowserModel
    var body: some View {
        ZStack {
            BrowserBackdrop()
            VStack(spacing: 0) {
                TabStrip(model: model)
                Toolbar(model: model)
                if let tab = model.selectedTab {
                    TabContent(model: model, tab: tab)
                } else {
                    EmptyTabView(model: model)
                }
            }
        }
        .frame(minWidth: 760, minHeight: 480)
        .tint(BPalette.rampartTeal)
    }
}

// MARK: - Tabs

struct TabStrip: View {
    @Bindable var model: BrowserModel
    var body: some View {
        HStack(spacing: 4) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 4) {
                    ForEach(model.tabs) { tab in
                        TabChip(tab: tab, selected: tab.id == model.selectedTabID || (model.selectedTabID == nil && tab.id == model.tabs.first?.id),
                                select: { model.selectedTabID = tab.id }, close: { model.close(tab) })
                    }
                }
                .padding(.horizontal, 8)
            }
            ToolbarIconButton(symbol: "plus", help: "New Tab (⌘T)") { model.newTab() }.padding(.trailing, 8)
        }
        .frame(height: 34)
        .toolbarGlass()
    }
}

struct TabChip: View {
    let tab: BrowserTab
    let selected: Bool
    let select: () -> Void
    let close: () -> Void
    @StateVar private var hover = false
    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: tab.interstitial != nil ? "hand.raised.fill" : (tab.display.isWarning ? "exclamationmark.triangle.fill" : "globe"))
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(tab.interstitial != nil || tab.display.isWarning ? BPalette.amber : .secondary)
            Text(tab.title).font(.caption).lineLimit(1).frame(maxWidth: 160, alignment: .leading)
            Button(action: close) { Image(systemName: "xmark").font(.system(size: 9, weight: .bold)) }
                .buttonStyle(.plain).opacity(hover || selected ? 0.8 : 0).help("Close Tab (⌘W)")
        }
        .padding(.horizontal, 10).padding(.vertical, 5)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(selected ? Color.primary.opacity(0.10) : (hover ? Color.primary.opacity(0.05) : .clear)))
        .contentShape(Rectangle())
        .onTapGesture(perform: select)
        .onHover { hover = $0 }
    }
}

// MARK: - Toolbar / address bar

struct Toolbar: View {
    @Bindable var model: BrowserModel
    var body: some View {
        let tab = model.selectedTab
        VStack(spacing: 0) {
            HStack(spacing: 6) {
                ToolbarIconButton(symbol: "chevron.left", help: "Back (⌘[)", enabled: tab?.canGoBack == true || tab?.interstitial != nil) { tab?.goBack() }
                ToolbarIconButton(symbol: "chevron.right", help: "Forward (⌘])", enabled: tab?.canGoForward == true) { tab?.goForward() }
                ToolbarIconButton(symbol: tab?.isLoading == true ? "xmark" : "arrow.clockwise", help: tab?.isLoading == true ? "Stop (⌘.)" : "Reload (⌘R)") {
                    if tab?.isLoading == true { tab?.stop() } else { tab?.reload() }
                }
                AddressBar(model: model, tab: tab)
                ShieldButton(model: model)
                ToolbarIconButton(symbol: "arrow.down.circle", help: "Downloads (⌘⇧J)") { model.showDownloads.toggle() }
                    .popover(isPresented: $model.showDownloads, arrowEdge: .bottom) { DownloadsPanel(model: model).frame(width: 380) }
            }
            .padding(.horizontal, 10).padding(.vertical, 7)
            // Progress hairline.
            ZStack(alignment: .leading) {
                Color.clear.frame(height: 2)
                if let tab, tab.isLoading {
                    GeometryReader { g in
                        Capsule().fill(LinearGradient(colors: [BPalette.teal, BPalette.mint], startPoint: .leading, endPoint: .trailing))
                            .frame(width: max(12, g.size.width * tab.progress), height: 2)
                    }
                }
            }
            .frame(height: 2)
        }
        .toolbarGlass()
        .overlay(alignment: .bottom) { Divider().opacity(0.4) }
    }
}

struct AddressBar: View {
    @Bindable var model: BrowserModel
    let tab: BrowserTab?
    @StateVar private var text = ""
    @StateVar private var editing = false
    @FocusState private var focused: Bool
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        let d = tab?.display ?? DomainDisplay.make(url: nil)
        HStack(spacing: 8) {
            Button { model.showIdentity.toggle() } label: {
                Image(systemName: d.lockSymbol)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(d.isWarning ? BPalette.amber : (d.identity == .secure ? BPalette.mint : .secondary))
                    .frame(width: 18)
            }
            .buttonStyle(.plain)
            .help(d.identityLabel)
            .accessibilityLabel(d.identityLabel)
            .popover(isPresented: $model.showIdentity, arrowEdge: .bottom) { IdentitySheet(tab: tab).frame(width: 360) }

            ZStack(alignment: .leading) {
                if editing {
                    TextField("Search or enter an address", text: $text)
                        .textFieldStyle(.plain)
                        .focused($focused)
                        .onSubmit { editing = false; focused = false; tab?.loadTyped(text) }
                        .onExitCommand { editing = false; focused = false }
                } else {
                    DomainLabel(display: d)
                        .contentShape(Rectangle())
                        .onTapGesture { text = d.fullText; editing = true; focused = true }
                }
            }
            .font(.system(size: 13))

            if d.isWarning, !editing {
                Text(d.identityLabel)
                    .font(.caption2.weight(.semibold))
                    .padding(.horizontal, 7).padding(.vertical, 2)
                    .background(BPalette.amber.opacity(0.18), in: Capsule())
                    .foregroundStyle(BPalette.amber)
                    .lineLimit(1)
            }
        }
        .padding(.horizontal, 10).frame(height: 30)
        .background(RoundedRectangle(cornerRadius: 9, style: .continuous).fill(scheme == .dark ? Color.white.opacity(0.07) : Color.black.opacity(0.05)))
        .overlay(RoundedRectangle(cornerRadius: 9, style: .continuous).strokeBorder(focused ? BPalette.rampartTeal.opacity(0.7) : Color.primary.opacity(0.08), lineWidth: 1))
        .onChange(of: model.addressFocusToken) { _, _ in text = d.fullText; editing = true; focused = true }
        .onChange(of: focused) { _, f in if !f { editing = false } }
        .onChange(of: model.selectedTabID) { _, _ in editing = false }
    }
}

/// Registrable domain bold and bright; scheme/subdomain and path dimmed; look-alike/punycode in amber.
struct DomainLabel: View {
    let display: DomainDisplay
    var body: some View {
        HStack(spacing: 0) {
            if display.domain.isEmpty {
                Text("Search or enter an address").foregroundStyle(.tertiary)
            } else {
                Text(display.prefix).foregroundStyle(.tertiary)
                Text(display.domain).fontWeight(.semibold).foregroundStyle(display.isWarning ? BPalette.amber : .primary)
                Text(display.suffixPath).foregroundStyle(.tertiary)
            }
        }
        .lineLimit(1).truncationMode(.tail)
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityLabel(display.fullText.isEmpty ? "Address" : display.fullText)
    }
}

struct ShieldButton: View {
    @Bindable var model: BrowserModel
    var body: some View {
        Button { model.showShieldMenu.toggle() } label: {
            HStack(spacing: 4) {
                Image(systemName: "checkmark.shield.fill").font(.system(size: 13, weight: .semibold))
                if model.blockedCount > 0 { Text("\(model.blockedCount)").font(.caption2.weight(.bold)) }
            }
            .foregroundStyle(BPalette.rampartTeal)
            .padding(.horizontal, 8).frame(height: 26)
            .background(RoundedRectangle(cornerRadius: 7, style: .continuous).fill(BPalette.rampartTeal.opacity(0.12)))
        }
        .buttonStyle(.plain)
        .help("RamPart protection")
        .popover(isPresented: $model.showShieldMenu, arrowEdge: .bottom) { ShieldPanel(model: model).frame(width: 360) }
    }
}

// MARK: - Content area

struct TabContent: View {
    @Bindable var model: BrowserModel
    let tab: BrowserTab
    var body: some View {
        ZStack {
            if let inter = tab.interstitial {
                InterstitialView(interstitial: inter, host: tab.blockedURL.map { DomainDisplay.make(url: $0).domain } ?? "",
                                 goBack: { tab.goBack() }, continueAnyway: { tab.continueAnyway() })
            } else if Headless.active {
                Color.clear
            } else {
                WebViewHost(webView: tab.webView)
            }
            VStack(spacing: 0) {
                if case .clean = tab.pageVerdict {} else if tab.interstitial == nil { FindingsBanner(verdict: tab.pageVerdict) }
                if model.showFind { FindBar(model: model, tab: tab) }
                if let e = tab.loadError, tab.interstitial == nil { ErrorBanner(text: e) }
                Spacer()
            }
            if let p = tab.permissionPrompt { PermissionSheet(prompt: p) { tab.permissionPrompt = nil } }
            if let d = tab.dialog { DialogSheet(dialog: d) { tab.dialog = nil } }
        }
    }
}

struct WebViewHost: NSViewRepresentable {
    let webView: WKWebView
    func makeNSView(context: Context) -> WKWebView { webView }
    func updateNSView(_ nsView: WKWebView, context: Context) {}
}

struct EmptyTabView: View {
    @Bindable var model: BrowserModel
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.shield.fill").font(.system(size: 56, weight: .semibold)).foregroundStyle(BPalette.rampartTeal)
            Text("RamPart Secure Browser").font(.title2.weight(.semibold)).fontDesign(.rounded)
            Text(model.bankingMode ? "Banking mode: nothing from this session is kept after you quit." : "Isolated profile: separate from Safari and from Banking mode.")
                .foregroundStyle(.secondary)
            Button("New Tab") { model.newTab() }.buttonStyle(GlowButton())
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Interstitial

struct InterstitialView: View {
    let interstitial: Interstitial
    let host: String
    let goBack: () -> Void
    let continueAnyway: () -> Void
    var tint: Color { interstitial.tone == .danger ? BPalette.coral : BPalette.amber }
    var body: some View {
        ZStack {
            BrowserBackdrop()
            VStack(alignment: .leading, spacing: 18) {
                HStack(spacing: 14) {
                    ZStack {
                        Circle().fill(tint.opacity(0.16)).frame(width: 64, height: 64)
                        Image(systemName: interstitial.symbol).font(.system(size: 28, weight: .semibold)).foregroundStyle(tint)
                    }
                    VStack(alignment: .leading, spacing: 4) {
                        Text(interstitial.title).font(.title2.weight(.semibold)).fontDesign(.rounded)
                        Text(host).font(.callout.monospaced()).foregroundStyle(.secondary)
                    }
                }
                Text(interstitial.body).font(.body).foregroundStyle(.primary).fixedSize(horizontal: false, vertical: true)
                if interstitial.reasons.count > 1 {
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(interstitial.reasons, id: \.self) { r in
                            Label(r, systemImage: "circle.fill").font(.callout).labelStyle(.titleAndIcon)
                                .imageScale(.small).foregroundStyle(.secondary)
                        }
                    }
                }
                HStack(spacing: 12) {
                    Button(interstitial.primaryLabel, action: goBack).buttonStyle(GlowButton()).keyboardShortcut(.defaultAction)
                    if interstitial.showsContinue, let s = interstitial.secondaryLabel {
                        Button(s, action: continueAnyway).buttonStyle(.plain).foregroundStyle(.secondary).font(.callout)
                    }
                    Spacer()
                    Label("RamPart", systemImage: "checkmark.shield.fill").font(.caption).foregroundStyle(BPalette.rampartTeal)
                }
                .padding(.top, 6)
            }
            .padding(28)
            .frame(maxWidth: 560)
            .bcard(tint: tint)
            .padding(40)
        }
        .accessibilityElement(children: .contain)
    }
}

// MARK: - Banners

struct FindingsBanner: View {
    let verdict: PageVerdict
    @StateVar private var expanded = false
    var severe: Bool { if case .warning = verdict { return true }; if case .block = verdict { return true }; return false }
    var body: some View {
        let f = verdict.findings
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Image(systemName: severe ? "exclamationmark.shield.fill" : "info.circle.fill").foregroundStyle(severe ? BPalette.amber : BPalette.teal)
                Text(f.first?.title ?? "").font(.callout.weight(.semibold))
                if f.count > 1 { Text("+\(f.count - 1) more").font(.caption).foregroundStyle(.secondary) }
                Spacer()
                Button(expanded ? "Hide" : "Why?") { expanded.toggle() }.buttonStyle(.plain).font(.callout).foregroundStyle(BPalette.rampartTeal)
            }
            if expanded {
                ForEach(f) { x in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(x.title).font(.callout.weight(.medium))
                        Text(x.explanation).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                        if let s = x.sample, !s.isEmpty { Text("“\(s)”").font(.caption.monospaced()).foregroundStyle(.tertiary).lineLimit(3) }
                    }
                }
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
        .background((severe ? BPalette.amber : BPalette.teal).opacity(0.14))
        .overlay(alignment: .bottom) { Divider() }
    }
}

struct ErrorBanner: View {
    let text: String
    var body: some View {
        HStack { Image(systemName: "wifi.exclamationmark"); Text(text).font(.callout); Spacer() }
            .padding(.horizontal, 14).padding(.vertical, 8).background(Color.secondary.opacity(0.12))
    }
}

struct FindBar: View {
    @Bindable var model: BrowserModel
    let tab: BrowserTab
    @StateVar private var q = ""
    @FocusState private var focused: Bool
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField("Find in page", text: $q).textFieldStyle(.plain).focused($focused)
                .onSubmit { tab.find(q) }.onExitCommand { model.showFind = false }
                .onChange(of: q) { _, v in tab.find(v) }
            if let m = tab.findMatches { Text(m > 0 ? "Found" : "Not found").font(.caption).foregroundStyle(.secondary) }
            ToolbarIconButton(symbol: "chevron.up", help: "Previous") { tab.find(q, forward: false) }
            ToolbarIconButton(symbol: "chevron.down", help: "Next") { tab.find(q) }
            ToolbarIconButton(symbol: "xmark", help: "Done") { model.showFind = false }
        }
        .padding(.horizontal, 12).padding(.vertical, 6).toolbarGlass()
        .onAppear { focused = true }
    }
}

// MARK: - Sheets (in-window, so pages can't impersonate system dialogs)

struct PermissionSheet: View {
    let prompt: PermissionPrompt
    let dismiss: () -> Void
    var body: some View {
        Color.black.opacity(0.35).ignoresSafeArea()
        VStack(alignment: .leading, spacing: 14) {
            Label("\(prompt.kind.rawValue) access", systemImage: prompt.kind == .microphone ? "mic.fill" : "video.fill").font(.title3.weight(.semibold))
            Text("\(prompt.origin) wants to use your \(prompt.kind.rawValue.lowercased()). RamPart never grants this automatically; allow it only if you started a call on this site.")
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Don't allow") { prompt.decide(false); dismiss() }.buttonStyle(GlowButton()).keyboardShortcut(.defaultAction)
                Button("Allow for this page") { prompt.decide(true); dismiss() }.buttonStyle(.plain).foregroundStyle(.secondary)
            }
        }
        .padding(22).frame(width: 420).bcard(tint: BPalette.amber)
    }
}

struct DialogSheet: View {
    let dialog: PageDialog
    let dismiss: () -> Void
    @StateVar private var text = ""
    var body: some View {
        Color.black.opacity(0.35).ignoresSafeArea()
        VStack(alignment: .leading, spacing: 12) {
            Text("The page at \(dialog.origin) says:").font(.caption).foregroundStyle(.secondary)
            Text(dialog.message).fixedSize(horizontal: false, vertical: true).lineLimit(12)
            if case .prompt(let def) = dialog.kind {
                TextField("", text: $text).textFieldStyle(.roundedBorder).onAppear { text = def }
            }
            HStack {
                Button("OK") { dialog.finish(true, text); dismiss() }.buttonStyle(GlowButton()).keyboardShortcut(.defaultAction)
                if case .alert = dialog.kind {} else { Button("Cancel") { dialog.finish(false, nil); dismiss() }.buttonStyle(.plain).foregroundStyle(.secondary) }
            }
        }
        .padding(22).frame(width: 420).bcard()
    }
}

// MARK: - Popovers

struct IdentitySheet: View {
    let tab: BrowserTab?
    var body: some View {
        let d = tab?.display ?? DomainDisplay.make(url: nil)
        let id = tab?.identity ?? IdentitySummary(host: d.domain, encrypted: d.scheme == "https")
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: d.lockSymbol).font(.title2).foregroundStyle(d.isWarning ? BPalette.amber : (d.identity == .secure ? BPalette.mint : .secondary))
                VStack(alignment: .leading) {
                    Text(d.domain.isEmpty ? "No site" : d.domain).font(.headline)
                    Text(d.identityLabel).font(.caption).foregroundStyle(.secondary)
                }
            }
            if !d.domain.isEmpty {
                Text(tab?.identity == nil ? "Certificate details appear once the page has loaded." : id.headline).font(.callout).fixedSize(horizontal: false, vertical: true)
                if let s = id.subject { row("Certificate for", s) }
                if let i = id.issuer { row("Issued by", i) }
                if case .lookalike(let b) = d.identity { row("Imitates", b) }
                if !d.asciiHost.isEmpty { row("Real address", d.asciiHost) }
                Text(id.caveat).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(16)
    }
    func row(_ k: String, _ v: String) -> some View {
        HStack(alignment: .top) { Text(k).foregroundStyle(.secondary).frame(width: 110, alignment: .leading); Text(v).textSelection(.enabled) }.font(.callout)
    }
}

struct ShieldPanel: View {
    @Bindable var model: BrowserModel
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "checkmark.shield.fill").foregroundStyle(BPalette.rampartTeal).font(.title2)
                VStack(alignment: .leading) {
                    Text("RamPart Secure Browser").font(.headline)
                    Text(model.bankingMode ? "Banking mode · session is not saved" : "Isolated profile · history kept").font(.caption).foregroundStyle(.secondary)
                }
            }
            Toggle("Banking mode (forget everything on quit)", isOn: Binding(get: { model.bankingMode }, set: { _ in model.toggleBankingMode() }))
                .toggleStyle(.switch).controlSize(.small)
            Divider()
            Group {
                line("lock.fill", "HTTPS only; plain HTTP is upgraded or warned about")
                line("eye.slash.fill", model.rulesStatus)
                line("list.bullet.rectangle", model.blocklistSummary)
                line("arrow.down.circle", model.daemonReachable == true ? "Downloads are scanned by the RamPart service" : "RamPart service not running: downloads that can run code stay quarantined")
                line("video.slash", "Camera and microphone always ask; location is never shared")
                line("puzzlepiece.extension", "No extensions can be installed")
            }
            if !model.activity.isEmpty {
                Divider()
                Text("This session").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                ForEach(model.activity.prefix(6)) { a in
                    HStack(spacing: 6) {
                        Image(systemName: a.severe ? "hand.raised.fill" : "exclamationmark.triangle.fill").foregroundStyle(a.severe ? BPalette.coral : BPalette.amber).font(.caption)
                        Text(a.host).font(.caption.monospaced()).lineLimit(1)
                        Text("· \(a.text)").font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
            }
            Text("Built on WebKit. macOS offers no supported way to run another engine or to prove JIT is off, so RamPart doesn't claim either.")
                .font(.caption2).foregroundStyle(.tertiary).fixedSize(horizontal: false, vertical: true)
        }
        .padding(16)
    }
    func line(_ s: String, _ t: String) -> some View {
        HStack(alignment: .top, spacing: 8) { Image(systemName: s).frame(width: 16).foregroundStyle(BPalette.rampartTeal); Text(t).font(.callout).fixedSize(horizontal: false, vertical: true) }
    }
}

struct DownloadsPanel: View {
    @Bindable var model: BrowserModel
    var downloads: DownloadManager { DownloadManager.shared }
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Downloads").font(.headline)
            if downloads.items.isEmpty {
                Text("Every download is quarantined and scanned before it appears in your Downloads folder.").font(.callout).foregroundStyle(.secondary)
            }
            ForEach(downloads.items) { item in DownloadRow(item: item) }
        }
        .padding(16)
    }
}

struct DownloadRow: View {
    let item: DownloadManager.Item
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Image(systemName: symbol).foregroundStyle(tint)
                VStack(alignment: .leading) {
                    Text(item.filename).font(.callout.weight(.medium)).lineLimit(1)
                    Text("\(item.cls.label) · \(item.sourceHost)").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }
            switch item.state {
            case .downloading(let p): ProgressView(value: p < 0 ? nil : p).controlSize(.small)
            case .scanning: HStack { ProgressView().controlSize(.small); Text("Scanning with RamPart…").font(.caption) }
            case .released: HStack { Text("Clean · in Downloads").font(.caption).foregroundStyle(BPalette.mint); Spacer(); Button("Show") { DownloadManager.shared.reveal(item.id) }.controlSize(.small) }
            case .held(let r, _):
                Text(r).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                HStack { Button("Delete") { DownloadManager.shared.delete(item.id) }.controlSize(.small); Button("Keep anyway") { DownloadManager.shared.releaseHeld(item.id) }.controlSize(.small) }
            case .blocked(let r, _):
                Text(r).font(.caption).foregroundStyle(BPalette.coral).fixedSize(horizontal: false, vertical: true)
                Button("Delete") { DownloadManager.shared.delete(item.id) }.controlSize(.small)
            case .failed(let e): Text(e).font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(10).bcard()
    }
    var symbol: String {
        switch item.state { case .blocked: return "xmark.octagon.fill"; case .held: return "exclamationmark.shield.fill"; case .released: return "checkmark.circle.fill"; default: return "arrow.down.circle" }
    }
    var tint: Color {
        switch item.state { case .blocked: return BPalette.coral; case .held: return BPalette.amber; case .released: return BPalette.mint; default: return BPalette.rampartTeal }
    }
}
