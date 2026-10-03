import SMPCore
import SMPServices
import SwiftUI

/// The middle column for the Tunnels section.
struct TunnelListView: View {
    @Bindable var model: TunnelsModel
    let hosts: HostsModel

    var body: some View {
        List(model.tunnels, selection: $model.selectedTunnelID) { tunnel in
            TunnelRow(model: model, tunnel: tunnel)
        }
        .overlay {
            if model.tunnels.isEmpty {
                ContentUnavailableView(
                    "No Tunnels",
                    systemImage: "point.3.connected.trianglepath.dotted",
                    description: Text("Save port forwards you use often and start them with one click.")
                )
            }
        }
        .navigationTitle("Tunnels")
        .navigationSplitViewColumnWidth(min: 260, ideal: 320)
        .toolbar {
            ToolbarItem {
                Button {
                    model.editing = TunnelProfile(
                        name: "New Tunnel",
                        hostAlias: hosts.connectableAliases.first ?? "",
                        forwards: [TunnelForward(bindPort: 8080, targetPort: 80)]
                    )
                } label: {
                    Label("New Tunnel", systemImage: "plus")
                }
            }
        }
        .sheet(item: $model.editing) { tunnel in TunnelEditSheet(model: model, hosts: hosts, tunnel: tunnel) }
        .task {
            model.reload()
            hosts.reload()
        }
    }
}

struct TunnelRow: View {
    let model: TunnelsModel
    let tunnel: TunnelProfile

    var body: some View {
        let state = model.state(of: tunnel)
        HStack {
            Circle()
                .fill(state.isRunning ? Color.green : (state == .stopped ? Color.secondary : Color.red))
                .frame(width: 9, height: 9)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(tunnel.name).fontWeight(.medium)
                Text("\(tunnel.hostAlias) · \(tunnel.forwards.map(Self.summary).joined(separator: ", "))")
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            Button(state.isRunning ? String(localized: "Stop") : String(localized: "Start")) { model.toggle(tunnel) }
                .controlSize(.small)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(tunnel.name), \(state.isRunning ? "running" : "stopped")")
    }

    static func summary(_ forward: TunnelForward) -> String {
        switch forward.kind {
        case .local: "L \(forward.bindPort)→\(forward.targetHost):\(forward.targetPort)"
        case .remote: "R \(forward.bindPort)→\(forward.targetHost):\(forward.targetPort)"
        case .dynamic: "SOCKS \(forward.bindPort)"
        }
    }
}

/// The detail column for the Tunnels section.
struct TunnelDetailView: View {
    let model: TunnelsModel
    let hosts: HostsModel

    var body: some View {
        if let tunnel = model.tunnels.first(where: { $0.id == model.selectedTunnelID }) {
            let state = model.state(of: tunnel)
            Form {
                Section {
                    LabeledContent("Host", value: tunnel.hostAlias)
                    LabeledContent("Status") {
                        switch state {
                        case .running: Text("Running").foregroundStyle(.green)
                        case .stopped: Text("Stopped").foregroundStyle(.secondary)
                        case .failed: Text("Failed").foregroundStyle(.red)
                        }
                    }
                    if case .failed(let message) = state {
                        Text(message).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        Text("Tunnels can't ask for passphrases: load the key into the agent first.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                Section("Forwards") {
                    ForEach(tunnel.forwards) { forward in
                        Text(forward.arguments.joined(separator: " ")).font(.system(.body, design: .monospaced))
                    }
                }
                Section {
                    HStack {
                        Button(state.isRunning
                            ? String(localized: "Stop")
                            : String(localized: "Start")) { model.toggle(tunnel) }
                        Button("Edit…") { model.editing = tunnel }
                        Spacer()
                        Button("Delete", role: .destructive) { model.delete(tunnel) }
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle(tunnel.name)
        } else {
            ContentUnavailableView("No Tunnel Selected", systemImage: "point.3.connected.trianglepath.dotted")
        }
    }
}

/// Creates or edits a tunnel profile.
struct TunnelEditSheet: View {
    let model: TunnelsModel
    let hosts: HostsModel
    @State var tunnel: TunnelProfile
    @Environment(\.dismiss) private var dismiss
    @State private var error: SMPError?

    var body: some View {
        Form {
            Section {
                TextField("Name", text: $tunnel.name)
                Picker("Host", selection: $tunnel.hostAlias) {
                    ForEach(hosts.connectableAliases, id: \.self) { Text($0).tag($0) }
                    if !hosts.connectableAliases.contains(tunnel.hostAlias) {
                        Text(tunnel.hostAlias.isEmpty
                            ? String(localized: "Choose a host")
                            : tunnel.hostAlias).tag(tunnel.hostAlias)
                    }
                }
            }
            ForEach($tunnel.forwards) { $forward in
                Section {
                    Picker("Type", selection: $forward.kind) {
                        Text("Local (-L)").tag(TunnelForward.Kind.local)
                        Text("Remote (-R)").tag(TunnelForward.Kind.remote)
                        Text("SOCKS (-D)").tag(TunnelForward.Kind.dynamic)
                    }
                    TextField("Bind address", text: $forward.bindAddress)
                    TextField("Port", value: $forward.bindPort, format: .number.grouping(.never))
                    if forward.kind != .dynamic {
                        TextField("Target host", text: $forward.targetHost)
                        TextField("Target port", value: $forward.targetPort, format: .number.grouping(.never))
                    }
                    if let problem = forward.problem {
                        Text(problem).font(.callout).foregroundStyle(.red)
                    }
                    Button("Remove Forward", role: .destructive) {
                        tunnel.forwards.removeAll { $0.id == forward.id }
                    }
                }
            }
            Section {
                Button("Add Forward") { tunnel.forwards.append(TunnelForward(bindPort: 8080, targetPort: 80)) }
            }
            if let error {
                Section { ErrorBanner(error: error) }
            }
        }
        .formStyle(.grouped)
        .frame(width: 460, height: 520)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button("Save") {
                    do {
                        try model.save(tunnel)
                        dismiss()
                    } catch {
                        self.error = error.asSMPError
                    }
                }
            }
        }
    }
}
