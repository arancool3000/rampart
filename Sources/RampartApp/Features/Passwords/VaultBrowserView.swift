import SwiftUI
import AppKit
import UniformTypeIdentifiers
import RampartVault
import RampartShared

/// Three columns: categories/folders/tags · item list · detail or editor.
struct VaultBrowserView: View {
    @Bindable private var model = PasswordsModel.shared
    @StateVar private var newFolder = ""
    @StateVar private var addingFolder = false

    var body: some View {
        HStack(spacing: 0) {
            sidebar.frame(width: 200)
            Divider()
            list.frame(width: 290)
            Divider()
            detail.frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    // MARK: Column 1

    private var sidebar: some View {
        List(selection: Binding(get: { model.filter }, set: { model.filter = $0 ?? .all })) {
            Section("Vault") {
                row("All Items", "tray.full", .all)
                row("Favourites", "star.fill", .favourites)
            }
            Section("Categories") {
                ForEach(VaultItemKind.allCases) { k in row(k.label + (k == .secureNote ? "s" : "s"), k.symbol, .kind(k)) }
            }
            Section {
                ForEach(model.meta.folders) { f in
                    row(f.name, "folder", .folder(f.id))
                        .contextMenu { Button("Delete Folder", role: .destructive) { model.deleteFolder(f.id) } }
                }
                if addingFolder {
                    TextField("Folder name", text: $newFolder)
                        .onSubmit { model.addFolder(newFolder); newFolder = ""; addingFolder = false }
                }
            } header: {
                HStack {
                    Text("Folders")
                    Spacer()
                    Button { addingFolder = true } label: { Image(systemName: "plus") }.buttonStyle(.borderless).help("New folder")
                }
            }
            if !model.allTags.isEmpty {
                Section("Tags") { ForEach(model.allTags, id: \.self) { t in row("#" + t, "tag", .tag(t)) } }
            }
        }
        .listStyle(.sidebar)
        .scrollContentBackground(.hidden)
    }

    private func row(_ title: String, _ symbol: String, _ f: PasswordsModel.Filter) -> some View {
        HStack {
            Label(title, systemImage: symbol)
            Spacer()
            Text("\(model.count(f))").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
        }
        .tag(f)
    }

    // MARK: Column 2

    private var list: some View {
        VStack(spacing: 0) {
            HStack(spacing: Spacing.s) {
                HStack {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("Search", text: $model.search).textFieldStyle(.plain)
                }
                .padding(7)
                .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                Menu {
                    ForEach(VaultItemKind.allCases) { k in Button { model.newItem(k) } label: { Label(k.label, systemImage: k.symbol) } }
                } label: { Image(systemName: "plus") }
                    .menuStyle(.borderlessButton).fixedSize().help("New item (⌘N)")
            }
            .padding(Spacing.m)
            let items = model.visibleItems
            if items.isEmpty {
                VStack(spacing: Spacing.s) {
                    Image(systemName: "key.horizontal").font(.largeTitle).foregroundStyle(.tertiary)
                    Text(model.items.isEmpty ? "Your vault is empty" : "No matching items").font(.headline)
                    if model.items.isEmpty {
                        Text("Add a login with +, or import from a browser in Settings.").font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
                    }
                }
                .padding().frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(items, selection: Binding(get: { model.selection }, set: { if $0 != model.selection { model.relockItem() }; model.selection = $0; model.editing = nil })) { i in
                    ItemRow(item: i).tag(i.id)
                }
                .scrollContentBackground(.hidden)
            }
        }
    }

    // MARK: Column 3

    @ViewBuilder private var detail: some View {
        if let e = model.editing, model.isItemHidden(e), model.store.item(e.id) != nil {
            LockedItemOverlay(item: e)
        } else if let e = model.editing {
            ItemEditor(item: e)
                .id(e.id)
        } else if let i = model.selectedItem {
            ItemDetail(item: i)
                .id(i.id)
        } else {
            VStack(spacing: Spacing.m) {
                IconBadge(symbol: "lock.rectangle.stack.fill", size: 56)
                Text("\(model.items.count) item\(model.items.count == 1 ? "" : "s"), encrypted").font(.title3.weight(.semibold))
                Text("Select an item to view it.").foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

struct ItemRow: View {
    let item: VaultItem
    @Bindable private var model = PasswordsModel.shared
    var body: some View {
        HStack(spacing: Spacing.m) {
            IconBadge(symbol: item.kind.symbol, tint: tint, size: 30)
            VStack(alignment: .leading, spacing: 1) {
                Text(item.title).lineLimit(1)
                Text(model.isItemHidden(item) && item.kind == .secureNote ? "Locked" : item.subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            if model.meta.requiresItemUnlock(item) { Image(systemName: "lock.fill").font(.caption).foregroundStyle(.secondary).accessibilityLabel("Locked item") }
            if item.favourite { Image(systemName: "star.fill").font(.caption).foregroundStyle(Palette.amber) }
        }
        .padding(.vertical, 2)
    }
    private var tint: Color {
        switch item.kind { case .login: return .rampartTeal; case .card: return .indigo; case .wifi: return .blue; case .totp: return Palette.mint; case .secureNote: return Palette.amber }
    }
}

// MARK: - Detail

struct ItemDetail: View {
    let item: VaultItem
    @Bindable private var model = PasswordsModel.shared
    @StateVar private var reveal = false
    @StateVar private var confirmDelete = false

    var body: some View {
        if model.isItemHidden(item) {
            LockedItemOverlay(item: item)
        } else {
            content.onDisappear { if model.editing?.id != item.id { model.relockItem() } }
        }
    }

    private var content: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.l) {
                HStack(spacing: Spacing.m) {
                    IconBadge(symbol: item.kind.symbol, size: 44)
                    VStack(alignment: .leading) {
                        Text(item.title).font(.title2.weight(.semibold)).fontDesign(.rounded)
                        Text(item.kind.label + (item.passwordModified.map { " · password changed " + Fmt.ago($0) } ?? "")).font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button { model.toggleFavourite(item) } label: { Image(systemName: item.favourite ? "star.fill" : "star") }
                        .buttonStyle(.borderless).foregroundStyle(item.favourite ? Palette.amber : .secondary).help("Favourite")
                    if model.meta.requiresItemUnlock(item) {
                        Button { model.relockItem() } label: { Label("Lock", systemImage: "lock.fill") }
                            .buttonStyle(.borderless).help("Hide this item again")
                    }
                    Button("Edit") { model.editing = item }.secondaryActionStyle()
                }
                if item.kind != .secureNote || !item.customFields.isEmpty {
                    VStack(spacing: 0) { fields }.card(padding: Spacing.s)
                }
                if let totp = item.totp { TOTPView(totp: totp) }
                if !item.notes.isEmpty, item.kind != .secureNote || true {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Notes").font(.caption).foregroundStyle(.secondary)
                        Text(item.notes).textSelection(.enabled)
                    }.card()
                }
                if !item.attachments.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Attachments").font(.caption).foregroundStyle(.secondary)
                        ForEach(item.attachments) { a in
                            HStack {
                                Label(a.name, systemImage: "paperclip")
                                Spacer()
                                Text(Fmt.bytes(UInt64(a.data.count))).font(.caption).foregroundStyle(.secondary)
                                Button("Save…") { saveAttachment(a) }.controlSize(.small)
                            }
                        }
                    }.card()
                }
                if !item.passwordHistory.isEmpty {
                    DisclosureGroup("Password history (\(item.passwordHistory.count))") {
                        ForEach(Array(item.passwordHistory.enumerated()), id: \.offset) { _, h in
                            HStack {
                                Text(reveal ? h.password : String(repeating: "•", count: 10)).font(.body.monospaced())
                                Spacer()
                                Text(Fmt.dayTime(h.replaced)).font(.caption).foregroundStyle(.secondary)
                                Button { model.copy(h.password, label: "Old password") } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.borderless)
                            }
                        }
                    }.card()
                }
                HStack {
                    if item.kind == .login && !item.password.isEmpty {
                        Button { model.saveToKeychain(item) } label: { Label("Save to Keychain", systemImage: "key.icloud") }
                            .help("Adds this login to your macOS login keychain so Safari and other apps can use it.")
                    }
                    Spacer()
                    Button("Delete", role: .destructive) { confirmDelete = true }
                }
                Text("Created \(Fmt.dayTime(item.created)) · Modified \(Fmt.dayTime(item.modified))").font(.caption2).foregroundStyle(.tertiary)
            }
            .padding(Spacing.xl)
        }
        .confirmationDialog("Delete “\(SafeText.line(item.title, max: 60))”?", isPresented: $confirmDelete) {
            Button("Delete", role: .destructive) { model.delete(item.id) }
        } message: { Text("An encrypted backup of the vault is kept, but the item disappears from the vault now.") }
    }

    @ViewBuilder private var fields: some View {
        switch item.kind {
        case .login, .totp:
            if !item.username.isEmpty { FieldRow(label: "Username", value: item.username) }
            if !item.password.isEmpty {
                FieldRow(label: "Password", value: item.password, secret: true, reveal: $reveal,
                         footer: AnyView(StrengthMeter(strength: PasswordStrength.evaluate(item.password, userInputs: [item.username, item.title]))))
            }
            ForEach(item.urls, id: \.self) { u in FieldRow(label: "Website", value: u, link: true) }
        case .card:
            if let c = item.card {
                FieldRow(label: "Cardholder", value: c.holder)
                FieldRow(label: "Number", value: c.number, secret: true, reveal: $reveal)
                FieldRow(label: "Expires", value: "\(c.expiryMonth)/\(c.expiryYear)")
                FieldRow(label: "Security code", value: c.cvv, secret: true, reveal: $reveal)
                if !c.pin.isEmpty { FieldRow(label: "PIN", value: c.pin, secret: true, reveal: $reveal) }
            }
        case .wifi:
            if let w = item.wifi {
                FieldRow(label: "Network", value: w.ssid)
                FieldRow(label: "Password", value: item.password, secret: true, reveal: $reveal)
                FieldRow(label: "Security", value: w.security + (w.hidden ? " (hidden)" : ""))
            }
        case .secureNote:
            EmptyView()
        }
        ForEach(item.customFields) { f in FieldRow(label: f.name, value: f.value, secret: f.concealed, reveal: $reveal) }
    }

    private func saveAttachment(_ a: Attachment) {
        let p = NSSavePanel(); p.nameFieldStringValue = a.name
        if p.runModal() == .OK, let u = p.url { try? PasswordsModel.writePrivate(a.data, to: u) }
    }
}

struct FieldRow: View {
    let label: String
    let value: String
    var secret = false
    var reveal: Binding<Bool>? = nil
    var link = false
    var footer: AnyView? = nil
    @Bindable private var model = PasswordsModel.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            HStack {
                let shown = !secret || (reveal?.wrappedValue ?? false)
                Text(shown ? value : String(repeating: "•", count: min(16, max(8, value.count))))
                    .font(secret ? .body.monospaced() : .body)
                    .textSelection(.enabled)
                    .lineLimit(2)
                Spacer()
                if secret, let reveal {
                    Button { reveal.wrappedValue.toggle() } label: { Image(systemName: reveal.wrappedValue ? "eye.slash" : "eye") }
                        .buttonStyle(.borderless).help(reveal.wrappedValue ? "Hide" : "Reveal")
                }
                if link, let url = URL(string: value.contains("://") ? value : "https://" + value) {
                    Link(destination: url) { Image(systemName: "arrow.up.right.square") }.help("Open website")
                }
                Button { model.copy(value, label: label) } label: { Image(systemName: "doc.on.doc") }
                    .buttonStyle(.borderless).help("Copy")
            }
            if let footer { footer.padding(.top, 2) }
        }
        .padding(.horizontal, Spacing.m).padding(.vertical, Spacing.s)
    }
}

/// Live RFC 6238 code with a countdown ring. Ticks once a second only while visible.
struct TOTPView: View {
    let totp: TOTP
    @Bindable private var model = PasswordsModel.shared
    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { ctx in
            let code = totp.code(at: ctx.date)
            let left = totp.secondsRemaining(at: ctx.date)
            HStack(spacing: Spacing.l) {
                ZStack {
                    Circle().stroke(Color.rampartTeal.opacity(0.15), lineWidth: 4)
                    Circle().trim(from: 0, to: Double(left) / Double(totp.period))
                        .stroke(left <= 5 ? Palette.coral : Color.rampartTeal, style: StrokeStyle(lineWidth: 4, lineCap: .round))
                        .rotationEffect(.degrees(-90))
                    Text("\(left)").font(.caption.monospacedDigit())
                }
                .frame(width: 36, height: 36)
                VStack(alignment: .leading) {
                    Text("One-time code").font(.caption).foregroundStyle(.secondary)
                    Text(grouped(code)).font(.system(size: 26, weight: .semibold, design: .monospaced)).foregroundStyle(left <= 5 ? Palette.coral : .primary)
                }
                Spacer()
                Button { model.copy(code, label: "Code") } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.borderless)
            }
            .card(tint: .rampartTeal)
        }
    }
    private func grouped(_ c: String) -> String {
        c.count == 6 || c.count == 8 ? c.prefix(c.count / 2) + " " + c.suffix(c.count / 2) : c
    }
}

// MARK: - Editor

struct ItemEditor: View {
    @StateVar var item: VaultItem
    @Bindable private var model = PasswordsModel.shared
    @StateVar private var showGenerator = false
    @StateVar private var urlText = ""
    @StateVar private var tagText = ""
    @StateVar private var reveal = true
    @StateVar private var requireUnlock = false

    init(item: VaultItem) {
        _requireUnlock = StateVar(initialValue: PasswordsModel.shared.meta.lockedItems.contains(item.id))
        _item = StateVar(initialValue: item)
        _urlText = StateVar(initialValue: item.urls.joined(separator: "\n"))
        _tagText = StateVar(initialValue: item.tags.joined(separator: ", "))
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.l) {
                HStack {
                    IconBadge(symbol: item.kind.symbol, size: 40)
                    TextField("\(item.kind.label) title", text: $item.title).textFieldStyle(.plain).font(.title2.weight(.semibold))
                }
                Form {
                    switch item.kind {
                    case .login, .totp:
                        TextField("Username or email", text: $item.username)
                        passwordField("Password")
                        if item.kind == .login {
                            TextField("Websites (one per line)", text: $urlText, axis: .vertical).lineLimit(1...4)
                        }
                        TextField("2FA secret or otpauth:// link", text: Binding(get: { item.totpSecret ?? "" }, set: { item.totpSecret = $0.isEmpty ? nil : $0 }))
                        if let s = item.totpSecret, !s.isEmpty, TOTP(string: s) == nil {
                            Text("That isn't a valid Base32 secret or otpauth link.").font(.caption).foregroundStyle(.orange)
                        }
                    case .card:
                        TextField("Cardholder", text: cardBinding(\.holder))
                        TextField("Card number", text: cardBinding(\.number))
                        HStack {
                            TextField("MM", text: cardBinding(\.expiryMonth)).frame(width: 60)
                            TextField("YYYY", text: cardBinding(\.expiryYear)).frame(width: 80)
                        }
                        SecureField("Security code", text: cardBinding(\.cvv))
                        SecureField("PIN", text: cardBinding(\.pin))
                    case .wifi:
                        TextField("Network name (SSID)", text: wifiBinding(\.ssid))
                        passwordField("Wi-Fi password")
                        Picker("Security", selection: wifiBinding(\.security)) {
                            ForEach(["WPA3 Personal", "WPA2/WPA3 Personal", "WPA2 Personal", "WPA/WPA2 Personal", "WEP", "None"], id: \.self) { Text($0).tag($0) }
                        }
                        Toggle("Hidden network", isOn: wifiBinding(\.hidden))
                    case .secureNote:
                        EmptyView()
                    }
                    TextField("Notes", text: $item.notes, axis: .vertical).lineLimit(3...12)
                    Picker("Folder", selection: $item.folderID) {
                        Text("None").tag(UUID?.none)
                        ForEach(model.meta.folders) { f in Text(f.name).tag(UUID?.some(f.id)) }
                    }
                    TextField("Tags (comma separated)", text: $tagText)
                    Toggle("Favourite", isOn: $item.favourite)
                    if item.kind == .secureNote {
                        LabeledContent("Require Touch ID to view") { Text("Always on for secure notes").foregroundStyle(.secondary) }
                    } else {
                        Toggle("Require Touch ID to view", isOn: $requireUnlock)
                    }
                    Text("Touch ID, your Mac's login password or your master password can show it. This hides the item on screen while the vault is open; it is not a second layer of encryption.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .formStyle(.grouped)
                .scrollContentBackground(.hidden)

                if showGenerator {
                    GeneratorPanel(onUse: { item.password = $0; showGenerator = false }).card()
                }

                VStack(alignment: .leading, spacing: Spacing.s) {
                    Text("Attachments (up to 1 MB each)").font(.caption).foregroundStyle(.secondary)
                    ForEach(item.attachments) { a in
                        HStack {
                            Label(a.name, systemImage: "paperclip"); Spacer()
                            Text(Fmt.bytes(UInt64(a.data.count))).font(.caption).foregroundStyle(.secondary)
                            Button { item.attachments.removeAll { $0.id == a.id } } label: { Image(systemName: "minus.circle") }.buttonStyle(.borderless)
                        }
                    }
                    Button { addAttachment() } label: { Label("Add Attachment…", systemImage: "paperclip") }.controlSize(.small)
                }
                .card()

                HStack {
                    Button("Cancel") { model.editing = nil }.keyboardShortcut(.cancelAction)
                    Spacer()
                    Button("Save") { commit() }.buttonStyle(GlowButtonStyle()).keyboardShortcut("s", modifiers: [.command])
                }
            }
            .padding(Spacing.xl)
        }
    }

    private func passwordField(_ title: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Group { if reveal { TextField(title, text: $item.password) } else { SecureField(title, text: $item.password) } }
                    .font(.body.monospaced())
                Button { reveal.toggle() } label: { Image(systemName: reveal ? "eye.slash" : "eye") }.buttonStyle(.borderless)
                Button { showGenerator.toggle() } label: { Image(systemName: "wand.and.stars") }.buttonStyle(.borderless).help("Generate")
            }
            if !item.password.isEmpty {
                StrengthMeter(strength: PasswordStrength.evaluate(item.password, userInputs: [item.username, item.title]))
                BreachBadge(password: item.password)
            }
        }
    }

    private func cardBinding(_ kp: WritableKeyPath<CardDetails, String>) -> Binding<String> {
        Binding(get: { item.card?[keyPath: kp] ?? "" }, set: { v in var c = item.card ?? CardDetails(); c[keyPath: kp] = v; item.card = c })
    }
    private func wifiBinding<T>(_ kp: WritableKeyPath<WiFiDetails, T>) -> Binding<T> {
        Binding(get: { (item.wifi ?? WiFiDetails())[keyPath: kp] }, set: { v in var w = item.wifi ?? WiFiDetails(); w[keyPath: kp] = v; item.wifi = w })
    }

    private func addAttachment() {
        let p = NSOpenPanel()
        guard p.runModal() == .OK, let u = p.url else { return }
        guard let d = try? Data(contentsOf: u) else { return }
        do { try item.addAttachment(name: u.lastPathComponent, data: d) } catch { model.error = error.localizedDescription }
    }

    private func commit() {
        item.urls = urlText.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        item.tags = tagText.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        let id = item.id, lock = requireUnlock, was = model.meta.lockedItems.contains(id)
        model.save(item)
        if lock != was { model.setItemLock(id, lock) }
    }
}

/// Shown instead of a locked item's content. Nothing of the item beyond its title is rendered.
struct LockedItemOverlay: View {
    let item: VaultItem
    @Bindable private var model = PasswordsModel.shared
    @StateVar private var master = ""
    @StateVar private var useMaster = false

    var body: some View {
        VStack(spacing: Spacing.m) {
            IconBadge(symbol: "lock.fill", size: 56)
            Text(item.title).font(.title2.weight(.semibold)).fontDesign(.rounded)
            Text("This item is locked. It locks again when you leave it, hide the window or after a minute idle.")
                .foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 360)
            Button { Task { await model.unlockItem(item) } } label: {
                Label("Unlock with \(model.availability.biometryName)", systemImage: "touchid")
            }
            .buttonStyle(GlowButtonStyle())
            if useMaster {
                HStack {
                    SecureField("Master password", text: $master).frame(maxWidth: 220)
                        .onSubmit(submitMaster)
                    Button("Unlock", action: submitMaster).disabled(master.isEmpty)
                }
            } else {
                Button("Use Master Password") { useMaster = true }.buttonStyle(.borderless)
            }
            if let e = model.itemUnlockError { Text(e).font(.caption).foregroundStyle(.orange) }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onDisappear { master = ""; model.itemUnlockError = nil }
    }

    private func submitMaster() {
        let pw = master; master = ""
        Task { await model.unlockItem(item, master: pw) }
    }
}
