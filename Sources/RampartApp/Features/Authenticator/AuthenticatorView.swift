import SwiftUI
import AppKit
import CoreImage
import UniformTypeIdentifiers
import ScreenCaptureKit
import RampartVault

/// Two-factor authenticator. Accounts are `.totp` items in the encrypted vault, so the screen reuses the
/// vault's lock (master password / Touch ID). Codes tick once a second only while the screen is visible.
struct AuthenticatorView: View {
    @Bindable private var model = PasswordsModel.shared
    @StateVar private var search = ""
    @StateVar private var sheet: AuthSheet?
    @StateVar private var dropActive = false

    enum AuthSheet: String, Identifiable { case add, importLinks, backup; var id: String { rawValue } }

    var body: some View {
        Group {
            switch model.phase {
            case .noVault: VaultLockScreen(creating: true)
            case .locked: VaultLockScreen(creating: false)
            case .unlocked: unlocked
            }
        }
        .navigationTitle("Authenticator")
        .overlay(alignment: .bottom) {
            if let t = model.toast {
                Label(t, systemImage: "checkmark.circle.fill").font(.callout.weight(.medium))
                    .padding(.horizontal, 14).padding(.vertical, 8).floatingGlassBar().padding(.bottom, Spacing.l)
            }
        }
        .onAppear { model.refreshPhase() }
        .sheet(item: $sheet) { s in
            switch s {
            case .add: AddAccountSheet()
            case .importLinks: ImportLinksSheet()
            case .backup: AuthenticatorBackupSheet()
            }
        }
    }

    private var filtered: [VaultItem] {
        let q = search.lowercased().trimmingCharacters(in: .whitespaces)
        return model.authenticatorItems.filter { q.isEmpty || $0.searchText.contains(q) || ($0.totp?.issuer?.lowercased().contains(q) ?? false) }
    }

    private var unlocked: some View {
        VStack(spacing: 0) {
            if let e = model.error {
                HStack { StatusLabel(text: e, symbol: "exclamationmark.triangle.fill", tint: .orange); Spacer(); Button("Dismiss") { model.error = nil }.controlSize(.small) }
                    .padding(.horizontal, Spacing.l).padding(.vertical, Spacing.s).background(Color.orange.opacity(0.12))
            }
            HStack {
                HStack {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("Search accounts", text: $search).textFieldStyle(.plain)
                }
                .padding(7).background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                Button { sheet = .add } label: { Label("Add Account", systemImage: "plus") }.keyboardShortcut("n", modifiers: [.command])
                Button { sheet = .importLinks } label: { Label("Import…", systemImage: "square.and.arrow.down") }
                Button { sheet = .backup } label: { Label("Back Up…", systemImage: "externaldrive") }
            }
            .padding(Spacing.m)
            let list = filtered
            if model.authenticatorItems.isEmpty {
                empty
            } else {
                List {
                    ForEach(list) { item in AuthCodeRow(item: item) }
                        .onMove(perform: search.isEmpty ? { model.moveAuthenticator(from: $0, to: $1) } : nil)
                }
                .scrollContentBackground(.hidden)
            }
            Text("Codes use this Mac's clock (\(Date().formatted(date: .omitted, time: .standard)) when the screen opened). If codes are rejected, turn on “Set time and date automatically” in System Settings › General › Date & Time.")
                .font(.caption).foregroundStyle(.secondary).padding(Spacing.m)
        }
        .onDrop(of: [.fileURL, .image], isTargeted: $dropActive) { providers in handleDrop(providers); return true }
        .overlay { if dropActive { RoundedRectangle(cornerRadius: 12).stroke(Color.rampartTeal, lineWidth: 3).padding(4) } }
    }

    private var empty: some View {
        VStack(spacing: Spacing.m) {
            IconBadge(symbol: "clock.badge.checkmark", size: 56)
            Text("No two-factor accounts yet").font(.title3.weight(.semibold))
            Text("Add one by hand, drop a QR code screenshot here, or import your accounts from Keyring, Google Authenticator, Aegis, 2FAS or Bitwarden.")
                .foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 420)
            HStack {
                Button("Add Account") { sheet = .add }.buttonStyle(GlowButtonStyle())
                Button("Import from Keyring…") { sheet = .importLinks }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func handleDrop(_ providers: [NSItemProvider]) {
        for p in providers {
            if p.canLoadObject(ofClass: NSImage.self) {
                _ = p.loadObject(ofClass: NSImage.self) { img, _ in
                    guard let img = img as? NSImage else { return }
                    let links = QRDecoder.decode(img)
                    Task { @MainActor in QRDecoder.addLinks(links) }
                }
            } else {
                _ = p.loadObject(ofClass: URL.self) { url, _ in
                    guard let url, let img = NSImage(contentsOf: url) else { return }
                    let links = QRDecoder.decode(img)
                    Task { @MainActor in QRDecoder.addLinks(links) }
                }
            }
        }
    }
}

/// One account: letter avatar, big live code, countdown ring, next code in the last 5 s, click to copy.
struct AuthCodeRow: View {
    let item: VaultItem
    @Bindable private var model = PasswordsModel.shared
    @StateVar private var showQR = false

    var body: some View {
        if let t = item.totp {
            TimelineView(.periodic(from: .now, by: 1)) { ctx in
                let code = t.code(at: ctx.date)
                let left = t.kind == .totp ? t.secondsRemaining(at: ctx.date) : t.period
                HStack(spacing: Spacing.l) {
                    LetterAvatar(text: Authenticator.initial(t), seed: t.issuer ?? item.title)
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 4) {
                            Text(t.issuer ?? item.title).font(.headline)
                            if item.favourite { Image(systemName: "pin.fill").font(.caption).foregroundStyle(Palette.amber) }
                        }
                        if let a = t.account { Text(a).font(.caption).foregroundStyle(.secondary).lineLimit(1) }
                        Button { model.copy(code, label: "Code") } label: {
                            Text(grouped(code)).font(.system(size: 30, weight: .semibold, design: .monospaced))
                                .foregroundStyle(t.kind == .totp && left <= 5 ? Palette.coral : .primary)
                                .contentTransition(.numericText())
                        }
                        .buttonStyle(.plain).help("Click to copy (clears from the clipboard after \(model.meta.settings.clipboardClearSeconds) s)")
                        .accessibilityLabel("Code \(code.map(String.init).joined(separator: " ")). Click to copy.")
                        if t.kind == .totp && left <= 5 {
                            Text("Next: \(grouped(t.code(at: ctx.date.addingTimeInterval(Double(t.period)))))").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        }
                    }
                    Spacer()
                    if t.kind == .totp {
                        ZStack {
                            Circle().stroke(Color.rampartTeal.opacity(0.15), lineWidth: 4)
                            Circle().trim(from: 0, to: Double(left) / Double(t.period))
                                .stroke(left <= 5 ? Palette.coral : Color.rampartTeal, style: StrokeStyle(lineWidth: 4, lineCap: .round))
                                .rotationEffect(.degrees(-90))
                            Text("\(left)").font(.caption.monospacedDigit())
                        }
                        .frame(width: 40, height: 40)
                        .accessibilityLabel("\(left) seconds left")
                    } else {
                        Button { model.advanceHOTP(item) } label: { Label("Next Code", systemImage: "arrow.forward.circle") }
                            .controlSize(.small).help("Counter-based (HOTP): \(t.counter)")
                    }
                }
                .padding(.vertical, 6)
            }
            .contextMenu {
                Button(item.favourite ? "Unpin" : "Pin to Top") { model.toggleFavourite(item) }
                Button("Show QR Code…") { showQR = true }
                Button("Delete", role: .destructive) { model.delete(item.id) }
            }
            .sheet(isPresented: $showQR) { SetupQRSheet(totp: t) }
        }
    }

    private func grouped(_ c: String) -> String {
        c.count == 6 || c.count == 8 ? c.prefix(c.count / 2) + " " + c.suffix(c.count / 2) : c
    }
}

struct LetterAvatar: View {
    let text: String
    let seed: String
    var body: some View {
        let palette: [Color] = [.rampartTeal, .indigo, .blue, Palette.mint, Palette.amber, Palette.coral, .purple, .pink]
        let i = Int(seed.unicodeScalars.reduce(0) { ($0 &* 31 &+ Int($1.value)) & 0xffff }) % palette.count
        Text(text).font(.title3.weight(.bold)).foregroundStyle(.white)
            .frame(width: 40, height: 40)
            .background(palette[i].gradient, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
            .accessibilityHidden(true)
    }
}

// MARK: - QR

enum QRDecoder {
    static func decode(_ image: NSImage) -> [String] {
        guard let tiff = image.tiffRepresentation, let ci = CIImage(data: tiff) else { return [] }
        return decode(ci)
    }
    static func decode(_ ci: CIImage) -> [String] {
        let det = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
        return (det?.features(in: ci) ?? []).compactMap { ($0 as? CIQRCodeFeature)?.messageString }
    }
    @MainActor static func addLinks(_ links: [String]) {
        let model = PasswordsModel.shared
        let r = Authenticator.parse(links.joined(separator: "\n"))
        if r.accounts.isEmpty { model.error = links.isEmpty ? "No QR code found in that image." : "That QR code isn't a two-factor setup code."; return }
        model.addAuthenticatorAccounts(r.accounts)
    }
    static func image(for text: String) -> NSImage? {
        guard let f = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        f.setValue(Data(text.utf8), forKey: "inputMessage"); f.setValue("M", forKey: "inputCorrectionLevel")
        guard let out = f.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)) else { return nil }
        let rep = NSCIImageRep(ciImage: out)
        let img = NSImage(size: rep.size); img.addRepresentation(rep)
        return img
    }
    /// Captures the main display ONLY when the user clicks "Scan QR on Screen". Needs Screen Recording permission.
    static func scanScreen() async -> [String] {
        guard !Headless.active else { return [] }
        do {
            let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
            guard let display = content.displays.first else { return [] }
            let filter = SCContentFilter(display: display, excludingWindows: [])
            let cfg = SCStreamConfiguration()
            cfg.width = display.width * 2; cfg.height = display.height * 2
            let cg = try await SCScreenshotManager.captureImage(contentFilter: filter, configuration: cfg)
            return decode(CIImage(cgImage: cg))
        } catch { return [] }
    }
}

struct SetupQRSheet: View {
    let totp: TOTP
    @Environment(\.dismiss) private var dismiss
    @StateVar private var revealed = false
    var body: some View {
        VStack(spacing: Spacing.m) {
            Text("Setup QR code for \(totp.issuer ?? totp.account ?? "account")").font(.title3.weight(.semibold))
            StatusLabel(text: "Anyone who scans this can generate your codes. Show it only to move the account to another device.", symbol: "exclamationmark.triangle.fill", tint: .orange)
                .font(.callout)
            if revealed, let img = QRDecoder.image(for: totp.uri) {
                Image(nsImage: img).interpolation(.none).resizable().frame(width: 220, height: 220)
            } else {
                Button("Show QR Code") { revealed = true }.buttonStyle(GlowButtonStyle()).frame(height: 220)
            }
            Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
        }
        .padding(Spacing.xl).frame(width: 420)
    }
}

// MARK: - Add account

struct AddAccountSheet: View {
    @Bindable private var model = PasswordsModel.shared
    @Environment(\.dismiss) private var dismiss
    @StateVar private var issuer = ""
    @StateVar private var account = ""
    @StateVar private var secret = ""
    @StateVar private var advanced = false
    @StateVar private var kind: TOTP.Kind = .totp
    @StateVar private var algorithm: TOTP.Algorithm = .sha1
    @StateVar private var digits = 6
    @StateVar private var period = 30
    @StateVar private var counter = 0
    @StateVar private var scanning = false

    private var draft: TOTP? {
        guard let sec = Authenticator.validSecret(secret) else { return nil }
        var t = TOTP(secret: sec, digits: digits, period: period, algorithm: algorithm,
                     issuer: issuer.trimmingCharacters(in: .whitespaces).isEmpty ? nil : issuer.trimmingCharacters(in: .whitespaces),
                     account: account.trimmingCharacters(in: .whitespaces).isEmpty ? nil : account.trimmingCharacters(in: .whitespaces))
        t.kind = kind; t.counter = UInt64(max(0, counter))
        return t
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            Text("Add a two-factor account").font(.title2.weight(.semibold))
            HStack {
                Button { chooseImage() } label: { Label("QR Code from Image…", systemImage: "qrcode.viewfinder") }
                Button { Task { scanning = true; let links = await QRDecoder.scanScreen(); scanning = false; if !links.isEmpty { QRDecoder.addLinks(links); dismiss() } else { model.error = "No QR code found on screen. If nothing happened, allow RamPart in System Settings › Privacy & Security › Screen Recording." } } } label: {
                    HStack { if scanning { ProgressView().controlSize(.small) }; Label("Scan QR on Screen", systemImage: "rectangle.dashed") }
                }
                .help("Takes one picture of your screen to find a QR code. macOS asks for Screen Recording permission the first time. Nothing is saved.")
            }
            Text("“Scan QR on Screen” takes a single picture of your display only when you click it, looks for a QR code, and discards it. macOS will ask for Screen Recording permission the first time.")
                .font(.caption).foregroundStyle(.secondary)
            Form {
                TextField("Service (issuer)", text: $issuer)
                TextField("Account (email or username)", text: $account)
                TextField("Secret key (Base32)", text: $secret).font(.body.monospaced())
                if !secret.isEmpty && Authenticator.validSecret(secret) == nil {
                    Text("That isn't valid Base32 (letters A–Z and digits 2–7).").font(.caption).foregroundStyle(.orange)
                }
                DisclosureGroup("Advanced", isExpanded: $advanced) {
                    Picker("Type", selection: $kind) { Text("Time-based (TOTP)").tag(TOTP.Kind.totp); Text("Counter-based (HOTP)").tag(TOTP.Kind.hotp) }
                    Picker("Algorithm", selection: $algorithm) { ForEach(TOTP.Algorithm.allCases, id: \.self) { Text($0.rawValue).tag($0) } }
                    Picker("Digits", selection: $digits) { Text("6").tag(6); Text("7").tag(7); Text("8").tag(8) }
                    if kind == .totp { Stepper("Period: \(period) s", value: $period, in: 10...120, step: 5) }
                    else { Stepper("Counter: \(counter)", value: $counter, in: 0...1_000_000) }
                }
                if let d = draft {
                    ForEach(Authenticator.warnings(d), id: \.self) { Label($0, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange) }
                    if model.items.compactMap(\.totp).contains(where: { Authenticator.dedupeKey($0) == Authenticator.dedupeKey(d) }) {
                        Label("This account is already in your authenticator.", systemImage: "doc.on.doc").font(.caption).foregroundStyle(.orange)
                    }
                }
            }
            .formStyle(.grouped)
            HStack {
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("Add") { if let d = draft { model.addAuthenticatorAccounts([d]); dismiss() } }
                    .buttonStyle(GlowButtonStyle()).disabled(draft == nil).keyboardShortcut(.defaultAction)
            }
        }
        .padding(Spacing.xl).frame(width: 520)
    }

    private func chooseImage() {
        let p = NSOpenPanel(); p.allowedContentTypes = [.image]
        guard p.runModal() == .OK, let u = p.url, let img = NSImage(contentsOf: u) else { return }
        let links = QRDecoder.decode(img)
        QRDecoder.addLinks(links)
        if !Authenticator.parse(links.joined(separator: "\n")).accounts.isEmpty { dismiss() }
    }
}

// MARK: - Import (Keyring links, Google migration, JSON)

struct ImportLinksSheet: View {
    @Bindable private var model = PasswordsModel.shared
    @Environment(\.dismiss) private var dismiss
    @StateVar private var text = ""

    var body: some View {
        let parsed = Authenticator.parse(text)
        let (kept, dup) = Authenticator.dedupe(parsed.accounts, against: model.items.compactMap(\.totp))
        VStack(alignment: .leading, spacing: Spacing.m) {
            Text("Import accounts").font(.title2.weight(.semibold))
            Text("From Keyring: open Back up & restore, choose Copy all, and paste here. Also accepts otpauth:// links (one per line), Google Authenticator export links (otpauth-migration://), and unencrypted Aegis, 2FAS or Bitwarden JSON.")
                .font(.callout).foregroundStyle(.secondary)
            TextEditor(text: $text).font(.caption.monospaced()).frame(minHeight: 120)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(.quaternary))
            if !text.isEmpty {
                Text("\(kept.count) new account\(kept.count == 1 ? "" : "s")\(dup > 0 ? ", \(dup) duplicate\(dup == 1 ? "" : "s") skipped" : "")").font(.headline)
                List(Array(kept.enumerated()), id: \.offset) { _, t in
                    HStack {
                        LetterAvatar(text: Authenticator.initial(t), seed: t.issuer ?? t.account ?? "")
                        VStack(alignment: .leading) {
                            Text(t.issuer ?? "No issuer"); Text(t.account ?? "").font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text("\(t.kind.rawValue.uppercased()) · \(t.algorithm.rawValue) · \(t.digits) digits").font(.caption).foregroundStyle(.secondary)
                        if !Authenticator.warnings(t).isEmpty { Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange).help(Authenticator.warnings(t).joined(separator: " ")) }
                    }
                }
                .frame(minHeight: 140)
                ForEach(parsed.errors.prefix(5), id: \.self) { Text($0).font(.caption).foregroundStyle(.orange) }
            }
            Text("After importing, clear the text you copied: setup links let anyone generate your codes.").font(.caption).foregroundStyle(.secondary)
            HStack {
                Button("Cancel") { text = ""; dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("Import \(kept.count)") { model.addAuthenticatorAccounts(kept); text = ""; dismiss() }
                    .buttonStyle(GlowButtonStyle()).disabled(kept.isEmpty)
            }
        }
        .padding(Spacing.xl).frame(width: 600, height: 560)
    }
}

// MARK: - Backup

struct AuthenticatorBackupSheet: View {
    @Bindable private var model = PasswordsModel.shared
    @Environment(\.dismiss) private var dismiss
    @StateVar private var exportPassword = ""
    @StateVar private var master = ""
    @StateVar private var links: String?
    @StateVar private var wrong = false

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            Text("Back up your authenticator").font(.title2.weight(.semibold))
            SectionHeader("Encrypted export")
            HStack {
                SecureField("Export password (10+ characters)", text: $exportPassword).frame(maxWidth: 260)
                Button("Export Encrypted…") { let p = exportPassword; Task { await model.exportAuthenticator(password: p); exportPassword = "" } }
                    .disabled(exportPassword.count < 10 || model.busy)
            }
            Divider()
            SectionHeader("Setup links")
            StatusLabel(text: "Anyone holding these links can generate your codes. Don't paste them into chats, notes or email.", symbol: "exclamationmark.triangle.fill", tint: .orange).font(.callout)
            if let links {
                ScrollView { Text(links).font(.caption.monospaced()).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                    .frame(height: 180).padding(6).background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 6))
                Button("Hide Links") { self.links = nil }
            } else {
                HStack {
                    SecureField("Master password", text: $master).frame(maxWidth: 260).onSubmit(reveal)
                    Button("Show Setup Links", action: reveal).disabled(master.isEmpty)
                }
                if wrong { Text("That master password is not correct.").font(.caption).foregroundStyle(.orange) }
            }
            HStack { Spacer(); Button("Done") { links = nil; dismiss() }.keyboardShortcut(.defaultAction) }
        }
        .padding(Spacing.xl).frame(width: 600)
        .onDisappear { links = nil; master = "" }
    }

    private func reveal() {
        let pw = master
        Task {
            let ok = await model.verifyMaster(pw)
            master = ""; wrong = !ok
            if ok { links = model.authenticatorItems.compactMap { $0.totp?.uri }.joined(separator: "\n") }
        }
    }
}
