import SMPAgent
import SMPCore
import SwiftUI

/// The login-item helper: runs SMP's SSH agent and shows its state in the menu bar.
@main
struct SMPAgentApp: App {
    @State private var controller = AgentController()

    var body: some Scene {
        MenuBarExtra {
            AgentMenu(controller: controller)
        } label: {
            Image(systemName: controller.isRunning ? "key.horizontal.fill" : "key.slash")
                .accessibilityLabel(controller.isRunning ? "SMP Agent is running" : "SMP Agent is stopped")
        }
        .menuBarExtraStyle(.window)
    }
}

struct AgentMenu: View {
    let controller: AgentController

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Circle()
                    .fill(controller.isRunning ? Color.green : Color.red)
                    .frame(width: 8, height: 8)
                    .accessibilityHidden(true)
                Text(controller.isRunning ? "SMP Agent is running" : "SMP Agent is stopped").font(.headline)
            }
            if let problem = controller.problem {
                Text(problem).font(.callout).foregroundStyle(.red)
                Button("Try Again") { controller.start() }
            }
            Text(summary).font(.caption).foregroundStyle(.secondary)
            Divider()
            Text("Recent requests").font(.subheadline.weight(.semibold))
            if controller.activity.isEmpty {
                Text("None yet").font(.caption).foregroundStyle(.secondary)
            } else {
                ForEach(controller.activity.prefix(8)) { entry in
                    ActivityRow(entry: entry)
                }
            }
            Divider()
            HStack {
                Button("Open SMP") { controller.openMainApp() }
                Button("Copy Config Line") { controller.copyIdentityAgentLine() }
                    .help(controller.identityAgentLine)
                Spacer()
                Button("Quit") { NSApplication.shared.terminate(nil) }
            }
        }
        .padding(14)
        .frame(width: 340)
        .onAppear { controller.refreshKeys() }
    }

    private var summary: String {
        let keys = controller.secureEnclaveKeyCount == 1
            ? "1 Secure Enclave key" : "\(controller.secureEnclaveKeyCount) Secure Enclave keys"
        let forwarding = controller.forwardsToSystemAgent
            ? "other keys come from the system ssh-agent" : "no system ssh-agent found"
        return "\(keys); \(forwarding)."
    }
}

struct ActivityRow: View {
    let entry: AgentActivity

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Image(systemName: symbol).foregroundStyle(color).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text("\(entry.peer) · \(entry.keyName)").font(.callout).lineLimit(1)
                Text("\(outcome) \(entry.date, style: .relative) ago")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private var outcome: String {
        switch entry.outcome {
        case .signed: "Signed"
        case .forwarded: "Signed by the system agent"
        case .declined: "Declined"
        case .refused: "Refused"
        case .failed: "Failed"
        }
    }

    private var symbol: String {
        switch entry.outcome {
        case .signed, .forwarded: "checkmark.circle.fill"
        case .declined, .refused: "hand.raised.fill"
        case .failed: "exclamationmark.triangle.fill"
        }
    }

    private var color: Color {
        switch entry.outcome {
        case .signed, .forwarded: .green
        case .declined, .refused: .orange
        case .failed: .red
        }
    }
}
