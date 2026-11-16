import SwiftUI
import RampartShared
import AppKit
import Combine

struct OnboardingView: View {
    enum Step: Int, CaseIterable { case welcome, applications, permissions, firstScan }
    /// True when the app is running from somewhere other than an Applications folder.
    static var needsMoveToApplications: Bool {
        let path = Bundle.main.bundlePath
        return !(path.hasPrefix("/Applications/") || path.hasPrefix(NSHomeDirectory() + "/Applications/"))
    }
    private var steps: [Step] {
        Step.allCases.filter { $0 != .applications || Self.needsMoveToApplications || step == .applications }
    }
    private var stepIndex: Int { steps.firstIndex(of: step) ?? 0 }
    var onFinish: () -> Void
    init(onFinish: @escaping () -> Void, initialStep: Step = .welcome) {
        self.onFinish = onFinish
        _step = StateVar(initialValue: initialStep)
    }
    @Environment(AppModel.self) private var model
    @Environment(\.openURL) private var openURL
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @StateVar private var step: Step = .welcome
    @StateVar private var scanStarted = false
    @StateVar private var drawn = false
    @StateVar private var showInstall = false

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: Spacing.m) {
                if step != .welcome {
                    Button { goBack() } label: { Label("Back", systemImage: "chevron.left") }
                        .buttonStyle(.link).help("Go to the previous step")
                        .disabled(step == .firstScan && scanStarted && model.isScanning)
                    Text("Step \(stepIndex) of \(steps.count - 1)").font(.callout).foregroundStyle(.secondary).monospacedDigit()
                }
                Spacer()
                if step != .firstScan {
                    Button("Skip for now") { advance() }.buttonStyle(.link).help("You can finish this later in Settings")
                }
            }
            .padding(.horizontal, Spacing.xl).padding(.top, Spacing.l)
            .frame(height: 40)

            Group {
                switch step {
                case .welcome: welcome
                case .applications: applications
                case .permissions: permissions
                case .firstScan: firstScan
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding(.horizontal, 48)
            .transition(.opacity)

            HStack(spacing: 6) {
                ForEach(steps, id: \.rawValue) { s in
                    Capsule()
                        .fill(s == step ? Color.rampartTeal : (s.rawValue < step.rawValue ? Color.rampartTeal.opacity(0.45) : Color.secondary.opacity(0.3)))
                        .frame(width: s == step ? 18 : 7, height: 7)
                }
            }
            .animation(reduceMotion ? nil : .easeInOut(duration: 0.25), value: step)
            .padding(.bottom, Spacing.l)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Step \(stepIndex + 1) of \(steps.count)")
        }
        .frame(width: 680, height: 600)
        .background(AppBackdrop())
        .sheet(isPresented: $showInstall) { InstallFullProtectionSheet() }
        .onReceive(NotificationCenter.default.publisher(for: .rampartOnboardingAdvance)) { _ in advance() }
        .onExitCommand { if step != .welcome && !(step == .firstScan && model.isScanning) { goBack() } }
    }

    private func advance() {
        withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.25)) {
            let i = stepIndex + 1
            if i < steps.count { step = steps[i] } else { onFinish() }
        }
    }

    private func goBack() {
        guard stepIndex > 0 else { return }
        withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.25)) { step = steps[stepIndex - 1] }
    }

    private var applications: some View {
        page(symbol: "folder.fill", title: "Move \(Product.name) to Applications",
             body: "\(Product.name) works best from your Applications folder. It keeps updates and background protection reliable. It only takes a second.") {
            Button("Show Me How") {
                NotificationCenter.default.post(name: .rampartShowMoveToApplications, object: nil)
            }
            .buttonStyle(GlowButtonStyle()).controlSize(.large)
            .padding(.top, Spacing.s)
            Button("Continue") { advance() }.keyboardShortcut(.defaultAction)
            Text("You can also do this later. Nothing is lost.").font(.callout).foregroundStyle(.secondary)
        }
    }

    private func page<Content: View>(symbol: String, tint: Color = .rampartTeal, title: String, body: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(spacing: Spacing.l) {
            Spacer()
            if symbol == "brand" {
                RamPartMark(size: 112)
            } else {
                ShieldHero(symbol: symbol, tint: tint, breathe: false, size: 112)
            }
            Text(title).font(.largeTitle.weight(.bold)).fontDesign(.monospaced).multilineTextAlignment(.center)
            Text(body).font(.title3).foregroundStyle(.secondary).multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
            content()
            Spacer()
        }
    }

    private var permissions: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            PermissionsChecklistView()
            HStack {
                Spacer()
                Button("Continue") { advance() }.buttonStyle(GlowButtonStyle()).controlSize(.large).keyboardShortcut(.defaultAction)
            }
        }
        .padding(.top, Spacing.s)
    }

    private var welcome: some View {
        page(symbol: "brand", title: "Welcome to \(Product.name)",
             body: "\(Product.name) protects your Mac quietly in the background. First we'll set up a few permissions in one place, then run a quick check. It takes about two minutes.") {
            Button("Get Started") { advance() }.buttonStyle(GlowButtonStyle()).controlSize(.large).keyboardShortcut(.defaultAction)
                .padding(.top, Spacing.s)
            Text("No ads. No upsells. Your files stay on your Mac.").font(.callout).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private var firstScan: some View {
        let p = model.scanProgress
        if case .finished(let rec, let found) = model.scanPhase, scanStarted {
            page(symbol: found.isEmpty ? "checkmark.shield.fill" : "archivebox.fill", tint: found.isEmpty ? .statusProtected : .gray,
                 title: found.isEmpty ? "All set. Your Mac is protected." : "Found \(found.count) item\(found.count == 1 ? "" : "s"). \(found.count == 1 ? "It's" : "They're") in quarantine and can't run.",
                 body: "Checked \(Fmt.count(rec.scanned)) files in \(Fmt.duration(rec.seconds)). Security Score: \(model.securityScore) · \(AppModel.scoreLabel(model.securityScore)).") {
                if !found.isEmpty {
                    VStack(spacing: 0) { ForEach(found.prefix(3)) { DetectionRowSummary(detection: $0).padding(Spacing.s) } }
                        .card(padding: Spacing.s).frame(maxWidth: 460)
                }
                if model.mode == .live && model.source == .basic {
                    VStack(spacing: Spacing.s) {
                        Text("Basic protection is running. For web protection and system-wide monitoring, enable full protection. macOS will ask for your password once.")
                            .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 460)
                        Button("Enable Full Protection…") { showInstall = true }
                    }
                }
                Button(found.isEmpty ? "Open \(Product.name)" : "Review") {
                    model.scanPhase = .idle
                    if !found.isEmpty { model.selection = .threats }
                    onFinish()
                }
                .buttonStyle(GlowButtonStyle()).controlSize(.large).keyboardShortcut(.defaultAction)
            }
        } else if model.mode == .connecting {
            page(symbol: "brand", title: "Starting protection…",
                 body: "\(Product.name) is starting its background checker. This only takes a moment and doesn't install anything.") {
                ProgressView().controlSize(.regular)
            }
            .onChange(of: model.mode) { _, m in if m != .connecting { beginFirstScan() } }
        } else if model.mode == .offline {
            page(symbol: "shield.slash", tint: .statusAction, title: "Protection service isn't running",
                 body: model.lastError ?? "\(Product.name) couldn't start its background checker, so it can't run a first scan yet.") {
                HStack {
                    Button("Retry") { Task { await model.retry(); beginFirstScan() } }.buttonStyle(GlowButtonStyle()).controlSize(.large)
                    if DaemonLauncher.shared.helperMissing { ReinstallButton().controlSize(.large) }
                    Button("Finish Without Scanning") { onFinish() }
                }
            }
        } else {
            page(symbol: "magnifyingglass", title: "Let's do a quick check",
                 body: "This usually takes about a minute. Feel free to close this window; the scan keeps going.") {
                Group {
                    if let f = p?.fraction { ProgressView(value: f) } else { ProgressView().progressViewStyle(.linear) }
                }
                .tint(Color.rampartTeal).frame(maxWidth: 360)
                Text(p.map { $0.fraction != nil ? "\(Fmt.count($0.scanned)) of \(Fmt.count($0.total)) files" : ($0.total > 0 ? "Finding files… \(Fmt.count($0.total)) so far" : "Finding files…") } ?? "Starting…")
                    .font(.callout).foregroundStyle(.secondary).monospacedDigit()
                if let cur = p?.current, !cur.isEmpty {
                    Text(cur.replacingOccurrences(of: NSHomeDirectory(), with: "~"))
                        .font(.caption.monospaced()).foregroundStyle(.tertiary).lineLimit(1).truncationMode(.middle).frame(maxWidth: 420)
                }
                if let n = p?.found, n > 0 { Text("\(n) item\(n == 1 ? "" : "s") found so far").font(.callout) }
                Button("Continue in Background") { onFinish() }.buttonStyle(.link)
            }
            .onAppear { beginFirstScan() }
        }
    }

    private func beginFirstScan() {
        guard !scanStarted, model.mode != .connecting, !Headless.active else { return }
        scanStarted = true
        if model.isScanning { return }
        model.scanPhase = .idle
        model.startScan(.quick)
    }
}

extension Notification.Name {
    /// Posted by onboarding when the user asks how to move the app into Applications.
    static let rampartShowMoveToApplications = Notification.Name("rampartShowMoveToApplications")
}

/// Shown when this copy of the app is missing its protection service file. Reveals the downloaded disk image
/// when one can be found; otherwise explains how to get a fresh copy.
struct ReinstallButton: View {
    @StateVar private var explain = false
    var body: some View {
        Button("Reinstall \(Product.name)…") {
            if !DaemonLauncher.shared.revealInstaller() { explain = true }
        }
        .help("Shows the \(Product.name) disk image in Finder so you can copy a fresh app into Applications.")
        .alert("Reinstall \(Product.name)", isPresented: $explain) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("\(Product.name) couldn't find its disk image in Downloads. Open the \(Product.name) .dmg you downloaded, drag \(Product.name) to Applications and replace this copy, then open it again. Your settings and quarantine are kept.")
        }
    }
}
