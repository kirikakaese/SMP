import AppKit
import SMPCore
import SMPServices
import SwiftUI

/// The middle column for SSH → Agent: status, setup and settings of SMP's agent.
struct AgentView: View {
    @Bindable var model: AgentModel
    @Bindable var hosts: HostsModel

    var body: some View {
        Form {
            statusSection
            sshSection
            settingsSection
        }
        .formStyle(.grouped)
        .navigationTitle("Agent")
        .navigationSplitViewColumnWidth(min: 340, ideal: 420)
        .toolbar {
            ToolbarItem {
                Button {
                    Task { await model.refresh() }
                } label: {
                    Label("Check Again", systemImage: "arrow.clockwise")
                }
                .disabled(model.isChecking)
            }
        }
        .sheet(
            item: $hosts.pendingChange,
            onDismiss: { Task { await model.refresh() } },
            content: { change in ConfigDiffSheet(model: hosts, change: change) }
        )
        .task { await model.refresh() }
    }

    private var statusSection: some View {
        Section {
            LabeledContent("SMP Agent") {
                HStack(spacing: 6) {
                    Circle().fill(statusColor).frame(width: 8, height: 8).accessibilityHidden(true)
                    Text(statusText)
                }
            }
            if let count = model.identityCount {
                LabeledContent("Keys offered", value: "\(count)")
            }
            switch model.helperStatus {
            case .notRegistered:
                Button("Start SMP Agent") { Task { await model.enable() } }
            case .requiresApproval:
                Text("macOS needs your permission to run SMP Agent in the background.")
                    .font(.callout)
                Button("Open Login Items Settings") { model.openLoginItemsSettings() }
            case .enabled:
                Button("Stop SMP Agent", role: .destructive) { Task { await model.disable() } }
            case .notFound:
                Text("This copy of SMP does not contain the agent helper.").foregroundStyle(.secondary)
            }
            if !model.socketPathFits {
                Text("Your home folder path is too long for the agent's socket. SSH cannot connect to it.")
                    .foregroundStyle(.red)
            }
        } header: {
            Text("Status")
        } footer: {
            Text("""
                SMP Agent starts at login and shows its state in the menu bar. It serves Secure Enclave \
                keys and passes everything else to the macOS ssh-agent.
                """)
                .foregroundStyle(.secondary)
        }
    }

    private var sshSection: some View {
        Section {
            LabeledContent("Used by ssh") {
                switch model.isUsedBySSH {
                case true?: Label("Yes", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                case false?: Text("Not yet").foregroundStyle(.secondary)
                case nil: Text("Unknown").foregroundStyle(.secondary)
                }
            }
            if model.isUsedBySSH != true {
                Button("Use SMP Agent for All Hosts…") { model.proposeConfigChange(using: hosts) }
                    .help("Adds IdentityAgent to a “Host *” block in ~/.ssh/config. You review it first.")
            }
            if let value = model.identityAgentValue {
                LabeledContent("Config line") {
                    Text("IdentityAgent \(value)")
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
                Button("Copy Config Line") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString("IdentityAgent \(value)", forType: .string)
                }
            }
        } header: {
            Text("SSH")
        } footer: {
            Text("""
                Hosts that set their own IdentityAgent keep it. Terminal sessions that rely on \
                SSH_AUTH_SOCK keep using the macOS agent directly.
                """)
                .foregroundStyle(.secondary)
        }
    }

    private var settingsSection: some View {
        Section {
            Toggle(
                "Ask for Touch ID before using keys from the macOS agent",
                isOn: $model.settings.confirmForwardedSignatures
            )
            Picker(
                "After approving, allow more signatures for",
                selection: $model.settings.forwardedReuseSeconds
            ) {
                Text("No time (ask every time)").tag(0)
                Text("1 minute").tag(60)
                Text("5 minutes").tag(300)
                Text("15 minutes").tag(900)
            }
            .disabled(!model.settings.confirmForwardedSignatures)
        } header: {
            Text("Keys in the macOS agent")
        } footer: {
            Text("""
                Secure Enclave keys follow their own Touch ID setting (see the key's details). \
                Approvals end when the screen locks or the Mac sleeps. Requests to add keys or lock \
                the agent are refused; add file keys with ssh-add as usual.
                """)
                .foregroundStyle(.secondary)
        }
    }

    private var statusText: String {
        switch model.helperStatus {
        case .enabled: model.identityCount == nil
            ? String(localized: "Starting or not responding")
            : String(localized: "Running")
        case .requiresApproval: String(localized: "Waiting for your approval")
        case .notRegistered: String(localized: "Off")
        case .notFound: String(localized: "Not available")
        }
    }

    private var statusColor: Color {
        switch model.helperStatus {
        case .enabled: model.identityCount == nil ? .orange : .green
        case .requiresApproval: .orange
        case .notRegistered, .notFound: .secondary
        }
    }
}

/// The detail column for SSH → Agent: how the pieces fit together.
struct AgentDetailView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("How SMP's agent works").font(.title2.weight(.semibold))
                step("1", "ssh connects to SMP Agent through the IdentityAgent setting.")
                step("2", """
                    Requests for Secure Enclave keys are signed inside the Secure Enclave after \
                    Touch ID. The private key never exists in memory or on disk.
                    """)
                step("3", """
                    Requests for other keys are passed on to the macOS ssh-agent, after Touch ID \
                    if you turned that on.
                    """)
                step("4", """
                    The menu bar shows which program asked for which key, so unexpected requests \
                    stand out.
                    """)
            }
            .padding(24)
            .frame(maxWidth: 560, alignment: .leading)
        }
    }

    private func step(_ number: String, _ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(number)
                .font(.headline)
                .frame(width: 24, height: 24)
                .background(Circle().fill(.quaternary))
                .accessibilityHidden(true)
            Text(text)
        }
    }
}
