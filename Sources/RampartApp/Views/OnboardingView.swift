import SwiftUI
import AppKit
import Combine

struct OnboardingView: View {
    enum Step: Int, CaseIterable { case welcome, fullDisk, notifications, firstScan }
    var onFinish: () -> Void
    @Environment(AppModel.self) private var model
    @Environment(\.openURL) private var openURL
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @StateVar private var step: Step = .welcome
    @StateVar private var fdaGranted = FDAProbe.check()
    @StateVar private var notifState: Bool? = nil
    @StateVar private var scanStarted = false
    @StateVar private var drawn = false
    private let poll = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                if step != .welcome {
                    Text("Step \(step.rawValue) of \(Step.allCases.count - 1)").font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                if step != .firstScan {
                    Button("Skip for now") { advance() }.buttonStyle(.link)
                }
            }
            .padding(.horizontal, Spacing.xl).padding(.top, Spacing.l)
            .frame(height: 40)

            Group {
                switch step {
                case .welcome: welcome
                case .fullDisk: fullDisk
                case .notifications: notifications
                case .firstScan: firstScan
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding(.horizontal, 48)
            .transition(.opacity)

            HStack(spacing: 8) {
                ForEach(Step.allCases, id: \.rawValue) { s in
                    Circle().fill(s == step ? Color.rampartTeal : Color.secondary.opacity(0.3)).frame(width: 7, height: 7)
                }
            }
            .padding(.bottom, Spacing.l)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Step \(step.rawValue + 1) of \(Step.allCases.count)")
        }
        .frame(width: 640, height: 520)
        .onReceive(NotificationCenter.default.publisher(for: .rampartOnboardingAdvance)) { _ in advance() }
        .onReceive(poll) { _ in
            if step == .fullDisk && !fdaGranted && FDAProbe.check() {
                fdaGranted = true
                model.hasFullDiskAccess = true
                DispatchQueue.main.asyncAfter(deadline: .now() + 1) { if step == .fullDisk { advance() } }
            }
        }
    }

    private func advance() {
        withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.25)) {
            if let next = Step(rawValue: step.rawValue + 1) { step = next } else { onFinish() }
        }
    }

    private func page<Content: View>(symbol: String, tint: Color = .rampartTeal, title: String, body: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(spacing: Spacing.l) {
            Spacer()
            Image(systemName: symbol).font(.system(size: 60)).foregroundStyle(tint).symbolRenderingMode(.hierarchical)
                .accessibilityHidden(true)
            Text(title).font(.largeTitle.weight(.semibold)).multilineTextAlignment(.center)
            Text(body).font(.title3).foregroundStyle(.secondary).multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
            content()
            Spacer()
        }
    }

    private var welcome: some View {
        page(symbol: "shield.lefthalf.filled", title: "Welcome to Rampart",
             body: "Rampart protects your Mac quietly in the background. We'll set up two permissions, then run a quick check. It takes about 2 minutes.") {
            Button("Get Started") { advance() }.buttonStyle(.borderedProminent).controlSize(.large).keyboardShortcut(.defaultAction)
                .padding(.top, Spacing.s)
            Text("No ads. No upsells. Your files stay on your Mac.").font(.callout).foregroundStyle(.secondary)
        }
    }

    private var fullDisk: some View {
        page(symbol: fdaGranted ? "checkmark.circle.fill" : "internaldrive", tint: fdaGranted ? .statusProtected : .rampartTeal,
             title: "Let Rampart check every folder",
             body: "macOS keeps some folders, like Mail and Messages, private by default. Full Disk Access lets Rampart scan them for threats. Rampart only checks files for malware; it doesn't read or upload your content.") {
            if fdaGranted {
                StatusLabel(text: "Full Disk Access is on", symbol: "checkmark.circle.fill", tint: .statusProtected).font(.headline)
            } else {
                Button("Open Privacy Settings") { openURL(FDAProbe.settingsURL) }
                    .buttonStyle(.borderedProminent).controlSize(.large).keyboardShortcut(.defaultAction)
                VStack(alignment: .leading, spacing: 6) {
                    Label("In System Settings, find **Rampart** in the list", systemImage: "1.circle")
                    Label("Turn its switch on and enter your password", systemImage: "2.circle")
                    Label("Come back here. This step ticks itself off.", systemImage: "3.circle")
                }
                .font(.callout).foregroundStyle(.secondary)
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text("Waiting for access…").font(.callout).foregroundStyle(.secondary)
                }
            }
        }
    }

    private var notifications: some View {
        page(symbol: "bell.badge", title: "Hear from us only when it matters",
             body: "We'll notify you if Rampart blocks a threat. Everything else stays in the app. You can change this anytime.") {
            // Rendered preview of a notification.
            HStack(alignment: .top, spacing: Spacing.m) {
                Image(systemName: "shield.lefthalf.filled").font(.title2).foregroundStyle(Color.rampartTeal)
                    .frame(width: 36, height: 36).background(.background, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                VStack(alignment: .leading, spacing: 2) {
                    Text("Rampart blocked a threat").font(.callout.weight(.semibold))
                    Text("\"Installer.app\" was moved to quarantine. No action needed unless you recognize it.").font(.callout).foregroundStyle(.secondary)
                }
            }
            .padding(Spacing.m)
            .frame(maxWidth: 400, alignment: .leading)
            .background(.background.secondary, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .accessibilityLabel("Example notification: Rampart blocked a threat.")
            HStack {
                Button("Not Now") { advance() }.controlSize(.large)
                Button("Allow Notifications") {
                    Task { notifState = await Notifier.shared.requestAuthorization(); advance() }
                }
                .buttonStyle(.borderedProminent).controlSize(.large).keyboardShortcut(.defaultAction)
            }
        }
    }

    @ViewBuilder private var firstScan: some View {
        let p = model.scanProgress
        if case .finished(let rec, let found) = model.scanPhase, scanStarted {
            page(symbol: found.isEmpty ? "checkmark.shield.fill" : "archivebox.fill", tint: found.isEmpty ? .statusProtected : .secondary,
                 title: found.isEmpty ? "All set. Your Mac is protected." : "Found \(found.count) item\(found.count == 1 ? "" : "s"). It's in quarantine and can't run.",
                 body: "Checked \(Fmt.count(rec.scanned)) files in \(Fmt.duration(rec.seconds)). Security Score: \(model.securityScore) · \(AppModel.scoreLabel(model.securityScore)).") {
                Button(found.isEmpty ? "Open Rampart" : "Review") {
                    model.scanPhase = .idle
                    if !found.isEmpty { model.selection = .threats }
                    onFinish()
                }
                .buttonStyle(.borderedProminent).controlSize(.large).keyboardShortcut(.defaultAction)
            }
        } else {
            page(symbol: "magnifyingglass", title: "Let's do a quick check",
                 body: "This takes about a minute. You can close this window — the scan continues.") {
                ProgressView(value: p?.fraction ?? 0).tint(Color.rampartTeal).frame(maxWidth: 360)
                Text(p.map { $0.total > 0 ? "\(Fmt.count($0.scanned)) of \(Fmt.count($0.total)) files" : "Estimating files…" } ?? "Starting…")
                    .font(.callout).foregroundStyle(.secondary).monospacedDigit()
                Button("Continue in Background") { onFinish() }.buttonStyle(.link)
            }
            .onAppear {
                guard !scanStarted else { return }
                scanStarted = true
                if model.isScanning { return }
                model.scanPhase = .idle
                model.startScan(.quick)
            }
        }
    }
}
