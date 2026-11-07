import SwiftUI
import RampartVault

/// Password / passphrase / PIN generator with a live strength meter. `onUse` puts the result into an editor.
struct GeneratorPanel: View {
    enum Mode: String, CaseIterable, Identifiable { case random = "Password", passphrase = "Passphrase", pronounceable = "Pronounceable", pin = "PIN"; var id: String { rawValue } }
    var onUse: ((String) -> Void)?
    @Bindable private var model = PasswordsModel.shared
    @StateVar private var mode: Mode = .random
    @StateVar private var options = PasswordGenerator.Options()
    @StateVar private var phrase = PasswordGenerator.PassphraseOptions()
    @StateVar private var pinLength = 6
    @StateVar private var pron = PasswordGenerator.PronounceableOptions()
    @StateVar private var ruleName = PasswordGenerator.siteRules[0].name
    @StateVar private var result = PasswordGenerator.Result(password: "", entropyBits: 0)
    @StateVar private var loaded = false

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.l) {
            if onUse == nil { SectionHeader("Password generator") }
            Picker("Type", selection: $mode) { ForEach(Mode.allCases) { Text($0.rawValue).tag($0) } }
                .pickerStyle(.segmented).labelsHidden()

            VStack(alignment: .leading, spacing: Spacing.m) {
                HStack(alignment: .center) {
                    Text(colored(result.password))
                        .font(.system(size: onUse == nil ? 22 : 17, weight: .medium, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(3)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Button { model.generatorHistory.add(result.password); regenerate() } label: { Image(systemName: "arrow.clockwise") }
                        .buttonStyle(.borderless).help("Generate another").keyboardShortcut("r", modifiers: [.command])
                    Button { model.generatorHistory.add(result.password); model.copy(result.password, label: "Password") } label: { Image(systemName: "doc.on.doc") }
                        .buttonStyle(.borderless).help("Copy (clears after \(model.meta.settings.clipboardClearSeconds) s)")
                }
                StrengthMeter(strength: PasswordStrength.known(entropyBits: result.entropyBits), compact: onUse != nil)
                BreachBadge(password: result.password)
                if let deadline = model.clipboardDeadline {
                    TimelineView(.periodic(from: .now, by: 1)) { ctx in
                        let left = max(0, Int(deadline.timeIntervalSince(ctx.date).rounded(.up)))
                        HStack {
                            Label("Clipboard clears in \(left) s", systemImage: "timer").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                            Button("Clear Now") { model.clearClipboardNow() }.controlSize(.small).buttonStyle(.borderless)
                        }
                    }
                }
            }
            .card(tint: StrengthMeter.tint(PasswordStrength.level(forBits: result.entropyBits)))

            VStack(alignment: .leading, spacing: Spacing.m) {
                switch mode {
                case .random:
                    sliderRow("Length", value: $options.length, range: 8...64)
                    HStack(spacing: Spacing.l) {
                        Toggle("a–z", isOn: $options.lowercase)
                        Toggle("A–Z", isOn: $options.uppercase)
                        Toggle("0–9", isOn: $options.digits)
                        Toggle("!@#", isOn: $options.symbols)
                    }
                    Toggle("Avoid look-alike characters (I l 1 O 0)", isOn: $options.excludeAmbiguous)
                    Picker("Site rules", selection: $ruleName) {
                        ForEach(PasswordGenerator.siteRules) { Text($0.name).tag($0.name) }
                    }
                    .help("Some sites limit length or symbols. Pick the rule the site asks for.")
                case .passphrase:
                    HStack {
                        Text("Presets")
                        ForEach(PasswordGenerator.passphrasePresets) { p in
                            Button(p.name) { phrase = p.options }.controlSize(.small)
                                .buttonStyle(.bordered).tint(phrase == p.options ? .rampartTeal : nil)
                        }
                    }
                    sliderRow("Words", value: $phrase.words, range: 3...10)
                    HStack {
                        Text("Separator")
                        Picker("Separator", selection: $phrase.separator) {
                            Text("Hyphen -").tag("-"); Text("Space").tag(" "); Text("Period .").tag("."); Text("Underscore _").tag("_"); Text("None").tag("")
                        }.labelsHidden().frame(width: 150)
                    }
                    Toggle("Capitalise words", isOn: $phrase.capitalize)
                    Toggle("Add a digit", isOn: $phrase.includeDigit)
                    Text("Words come from RamPart's built-in list of \(PasswordGenerator.wordlistCount.formatted()) common English words, so each adds \(String(format: "%.1f", log2(Double(PasswordGenerator.wordlistCount)))) bits.")
                        .font(.caption).foregroundStyle(.secondary)
                case .pronounceable:
                    sliderRow("Length", value: $pron.length, range: 8...40)
                    HStack(spacing: Spacing.l) {
                        Toggle("One capital", isOn: $pron.capitalize)
                        Toggle("Two digits", isOn: $pron.digits)
                        Toggle("A symbol", isOn: $pron.symbol)
                    }
                    Text("Alternating consonants and vowels are easier to read out and type, so each letter carries fewer bits. Use more length than you would for a random password.")
                        .font(.caption).foregroundStyle(.secondary)
                case .pin:
                    sliderRow("Digits", value: $pinLength, range: 4...12)
                    Text("PINs are only safe where attempts are limited (a phone or a bank card).").font(.caption).foregroundStyle(.secondary)
                }
            }
            .card()

            if !model.generatorHistory.entries.isEmpty {
                DisclosureGroup("Recently generated (\(model.generatorHistory.entries.count), kept in memory only until you lock)") {
                    ForEach(model.generatorHistory.entries) { e in
                        HStack {
                            Text(e.password).font(.callout.monospaced()).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                            Spacer()
                            Text(Fmt.ago(e.date)).font(.caption).foregroundStyle(.secondary)
                            Button { model.copy(e.password, label: "Password") } label: { Image(systemName: "doc.on.doc") }
                                .buttonStyle(.borderless).help("Copy")
                        }
                    }
                    Button("Clear History") { model.generatorHistory.clear() }.controlSize(.small)
                }
                .card()
            }

            if let onUse {
                Button { model.generatorHistory.add(result.password); onUse(result.password) } label: { Label("Use This Password", systemImage: "checkmark") }
                    .buttonStyle(GlowButtonStyle())
            } else {
                Text("Generated with macOS's cryptographic random number generator. Entropy shown is exact for these settings.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .onAppear {
            if !loaded { options = model.meta.settings.generator; phrase = model.meta.settings.passphrase; loaded = true }
            regenerate()
        }
        .onChange(of: mode) { _, _ in regenerate() }
        .onChange(of: options) { _, o in regenerate(); if model.phase == .unlocked { model.updateSettings { $0.generator = o } } }
        .onChange(of: phrase) { _, p in regenerate(); if model.phase == .unlocked { model.updateSettings { $0.passphrase = p } } }
        .onChange(of: pinLength) { _, _ in regenerate() }
        .onChange(of: pron) { _, _ in regenerate() }
        .onChange(of: ruleName) { _, _ in regenerate() }
    }

    private func sliderRow(_ title: String, value: Binding<Int>, range: ClosedRange<Int>) -> some View {
        HStack {
            Text(title).frame(width: 64, alignment: .leading)
            Slider(value: Binding(get: { Double(value.wrappedValue) }, set: { value.wrappedValue = Int($0.rounded()) }),
                   in: Double(range.lowerBound)...Double(range.upperBound), step: 1)
            Text("\(value.wrappedValue)").monospacedDigit().frame(width: 28, alignment: .trailing)
        }
    }

    private func regenerate() {
        switch mode {
        case .random:
            let rule = PasswordGenerator.siteRules.first { $0.name == ruleName } ?? PasswordGenerator.siteRules[0]
            result = PasswordGenerator.random(options, rule: rule)
        case .pronounceable: result = PasswordGenerator.pronounceable(pron)
        case .passphrase: result = PasswordGenerator.passphrase(phrase)
        case .pin: result = PasswordGenerator.pin(length: pinLength)
        }
    }

    /// Digits and symbols tinted so the password is easier to read.
    private func colored(_ s: String) -> AttributedString {
        var out = AttributedString()
        for ch in s {
            var a = AttributedString(String(ch))
            if ch.isNumber { a.foregroundColor = .rampartTeal } else if !ch.isLetter { a.foregroundColor = Palette.amber }
            out += a
        }
        return out
    }
}
