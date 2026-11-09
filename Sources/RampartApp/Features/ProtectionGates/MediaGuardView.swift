import SwiftUI
import RampartShared
import RampartGuard

/// "Camera & Mic": which app is using the camera or microphone right now, the history, and the trusted list.
struct MediaGuardView: View {
    @Bindable var model = MediaGuardModel.shared

    private var serious: Bool { model.tone == .serious }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                header
                if model.unsupported {
                    Label("The RamPart helper doesn't run Camera & Microphone Guard yet.", systemImage: "info.circle")
                        .foregroundStyle(.secondary).card(padding: Spacing.m)
                }
                if let e = model.error { Label(e, systemImage: "exclamationmark.triangle").foregroundStyle(.orange) }
                live
                settings
                history
                trusted
                limits
            }
            .contentColumn()
        }
        .task {
            while !Task.isCancelled {
                await model.refresh()
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
        .confirmationDialog("Stop \(model.confirmStop.map { name(for: $0) } ?? "this app")?",
                            isPresented: Binding(get: { model.confirmStop != nil }, set: { if !$0 { model.confirmStop = nil } })) {
            Button("Stop it", role: .destructive) {
                if let id = model.confirmStop { Task { await model.stop(id) } }
                model.confirmStop = nil
            }
        } message: {
            Text("RamPart asks the app to quit (and forces it after a few seconds). Unsaved work in it may be lost. macOS components are never stopped.")
        }
    }

    private func name(for appID: String) -> String {
        "'" + SafeText.line(model.status?.active.first { $0.appID == appID }?.appName ?? model.status?.recent.first { $0.appID == appID }?.appName ?? appID, max: 60) + "'"
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            Text("Camera & Mic").font(.largeTitle.weight(.bold)).fontDesign(.rounded)
            Text(model.cameraOn || model.micOn ? (serious ? "In use now." : "Someone's on air right now.") : (serious ? "Camera and microphone are off." : "All quiet. Nobody's watching or listening."))
                .font(.title3).foregroundStyle(.secondary)
            Text("RamPart tells you when an app you haven't trusted turns on your camera or microphone, or when either is used while your Mac is locked or you're away.")
                .font(.callout).foregroundStyle(.secondary)
        }
    }

    private var live: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            HStack(spacing: Spacing.m) {
                indicator("video.fill", "Camera", on: model.cameraOn)
                indicator("mic.fill", "Microphone", on: model.micOn)
                Spacer()
            }
            ForEach(model.status?.active ?? []) { s in
                HStack {
                    Image(systemName: s.device.symbol).foregroundStyle(.green)
                    VStack(alignment: .leading) {
                        Text(SafeText.line(s.appName, max: 60)).font(.headline)
                        TimelineView(.periodic(from: .now, by: 1)) { ctx in
                            Text("\(s.device.label.capitalized) on for \(Durations.text(s.duration(now: ctx.date)))\(s.system ? " · macOS component" : s.trusted ? " · trusted" : " · not trusted")")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    Spacer()
                    if !s.system && !s.unattributed {
                        if !s.trusted { Button("Trust this app") { Task { await model.trust(s.appID, true) } } }
                        Button("Stop it", role: .destructive) { model.confirmStop = s.appID }.disabled(model.busy)
                    }
                }
            }
            if let src = model.status?.source { Text("Source: \(src)").font(.caption2).foregroundStyle(.tertiary) }
            if let e = model.status?.sourceError { Text(e).font(.caption2).foregroundStyle(.orange) }
        }
        .card(padding: Spacing.m)
    }

    private func indicator(_ symbol: String, _ title: String, on: Bool) -> some View {
        HStack(spacing: 6) {
            Image(systemName: symbol)
            Text("\(title): \(on ? "on" : "off")").font(.headline)
        }
        .padding(.horizontal, 10).padding(.vertical, 6)
        .background((on ? Color.green : Color.secondary).opacity(on ? 0.25 : 0.12), in: Capsule())
        .accessibilityLabel("\(title) \(on ? "in use" : "off")")
    }

    private var settings: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            Toggle(isOn: Binding(get: { model.status?.enabled ?? true }, set: { v in Task { await model.setEnabled(v) } })) {
                Text("Watch the camera and microphone").font(.headline)
            }
            .toggleStyle(.switch).disabled(model.busy || model.unsupported)
            Picker("Alert style", selection: Binding(get: { serious }, set: { v in Task { await model.setTone(serious: v) } })) {
                Text("Playful").tag(false)
                Text("Serious").tag(true)
            }
            .pickerStyle(.segmented).frame(maxWidth: 280)
        }
        .card(padding: Spacing.m)
    }

    private var history: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            Text("Recent use").font(.title3.weight(.semibold))
            let recent = Array((model.status?.recent ?? []).prefix(40))
            if recent.isEmpty { Text("Nothing yet.").font(.callout).foregroundStyle(.secondary) }
            ForEach(recent) { s in
                HStack {
                    Image(systemName: s.device.symbol).foregroundStyle(s.alerted ? .orange : .secondary).frame(width: 22)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("\(SafeText.line(s.appName, max: 60)) · \(s.device.label) · \(Durations.text(s.duration()))").font(.callout)
                        Text("\(Fmt.dayTime(s.start))\(s.system ? " · macOS component" : s.trusted ? " · trusted" : " · not trusted")\(s.whileLocked ? " · while locked" : s.whileIdle ? " · while you were away" : "")")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                }
            }
        }
        .card(padding: Spacing.m)
    }

    private var trusted: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            Text("Trusted apps").font(.title3.weight(.semibold))
            let list = model.status?.config.trusted ?? []
            if list.isEmpty { Text("No apps yet. Choose \"Trust this app\" on an alert or above.").font(.callout).foregroundStyle(.secondary) }
            ForEach(list, id: \.self) { id in
                HStack {
                    Text(id).font(.callout.monospaced())
                    Spacer()
                    Button("Remove") { Task { await model.trust(id, false) } }
                }
            }
            Text("Trusted apps don't alert, except while your Mac is locked or you're away.").font(.caption).foregroundStyle(.secondary)
        }
        .card(padding: Spacing.m)
    }

    private var limits: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            Label("How this works", systemImage: "info.circle").font(.headline)
            Text(model.status?.honesty ?? MediaGuardService.honesty).font(.callout).foregroundStyle(.secondary)
        }
        .card(padding: Spacing.m)
    }
}
