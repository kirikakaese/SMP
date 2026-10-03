import SMPCore
import SMPServices
import SwiftUI

/// Whether the first-run introduction was finished.
public enum OnboardingState {
    private static let key = "onboarding.completed"

    public static func isCompleted(in defaults: UserDefaults = .standard) -> Bool {
        defaults.bool(forKey: key)
    }

    public static func setCompleted(_ completed: Bool, in defaults: UserDefaults = .standard) {
        defaults.set(completed, forKey: key)
    }
}

/// The first-run introduction: what SMP does, what it found, the app lock and SMP Agent.
struct OnboardingView: View {
    enum Step: Int, CaseIterable {
        case welcome, keys, lock, agent, done
    }

    let library: LibraryModel
    let security: SecurityModel
    @Bindable var appLock: AppLockModel
    let agent: AgentModel
    let onFinish: () -> Void

    @State private var step: Step = .welcome
    @State private var isStartingAgent = false

    var body: some View {
        VStack(spacing: 0) {
            Group {
                switch step {
                case .welcome: welcome
                case .keys: keys
                case .lock: lock
                case .agent: agentStep
                case .done: done
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .padding(32)
            Divider()
            HStack {
                Text("Step \(step.rawValue + 1) of \(Step.allCases.count)").foregroundStyle(.secondary)
                Spacer()
                if step != .welcome {
                    Button("Back") { move(by: -1) }
                }
                if step == .done {
                    Button("Get Started") { onFinish() }
                        .keyboardShortcut(.defaultAction)
                } else {
                    Button("Continue") { move(by: 1) }
                        .keyboardShortcut(.defaultAction)
                }
            }
            .padding(16)
        }
        .frame(width: 560, height: 440)
        .interactiveDismissDisabled()
    }

    private func move(by offset: Int) {
        step = Step(rawValue: step.rawValue + offset) ?? step
    }

    private var welcome: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Welcome to SSH Management Platform", systemImage: "key.horizontal.fill")
                .font(.title.weight(.semibold))
            Text("SMP keeps your SSH keys, hosts and agent in one place.")
            bullet("key", "Create, import and organise keys, and see which ones need attention.")
            bullet("server.rack", "Edit ~/.ssh/config safely: every change is shown as a diff and backed up.")
            bullet("lock.shield", "Keep keys in the Secure Enclave and confirm each use with Touch ID.")
            bullet("hand.raised", "Your keys stay on this Mac. SMP collects no telemetry and only talks to the "
                + "providers you add.")
        }
    }

    private var keys: some View {
        let count = library.items.filter { !$0.isArchived && !$0.isVirtualSecureEnclaveEntry }.count
        return VStack(alignment: .leading, spacing: 14) {
            Text("Your keys").font(.title2.weight(.semibold))
            Text(count == 0
                ? "SMP found no keys in ~/.ssh yet. Create one with File → New Key (⌘N)."
                : "SMP found \(count) \(count == 1 ? "key" : "keys") in ~/.ssh.")
            if count > 0 {
                LabeledContent("Security score", value: "\(security.score) of 100")
                Text(security.importantCount == 0
                    ? "Nothing important needs fixing."
                    : "\(security.importantCount) findings are worth a look in Security → Audit, most with "
                        + "a one-click fix.")
                    .foregroundStyle(.secondary)
            }
            Text("Add more folders to scan in Settings → Key Folders.").foregroundStyle(.secondary)
        }
    }

    private var lock: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("App lock").font(.title2.weight(.semibold))
            Text("SMP can hide its window until you confirm with Touch ID or your password: when it opens, "
                + "after a while without use, and when your screen locks.")
            if appLock.isAvailable {
                Toggle("Lock SMP", isOn: $appLock.settings.isEnabled)
                IdleLockPicker(settings: $appLock.settings)
                    .disabled(!appLock.settings.isEnabled)
            } else {
                Text("Your Mac has no login password, so the app lock is not available.")
                    .foregroundStyle(.secondary)
            }
            Text("Deleting or exporting keys always asks again, whether the lock is on or not.")
                .foregroundStyle(.secondary)
        }
    }

    private var agentStep: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("SMP Agent").font(.title2.weight(.semibold))
            Text("SMP Agent runs in the menu bar. It holds your Secure Enclave keys, signs with them after "
                + "Touch ID, and passes everything else on to the macOS ssh-agent.")
            HStack {
                Button(agent.helperStatus == .enabled ? "SMP Agent Is Running" : "Start SMP Agent") {
                    Task {
                        isStartingAgent = true
                        defer { isStartingAgent = false }
                        await agent.enable()
                    }
                }
                .disabled(agent.helperStatus == .enabled || isStartingAgent)
                if isStartingAgent { ProgressView().controlSize(.small) }
            }
            if agent.helperStatus == .requiresApproval {
                Text("Allow “SMP Agent” in System Settings → General → Login Items.")
                    .foregroundStyle(.orange)
            }
            Text("To let ssh use it, open SSH → Agent later; SMP shows the ~/.ssh/config change first. "
                + "You can skip this step.")
                .foregroundStyle(.secondary)
        }
        .task { await agent.refresh() }
    }

    private var done: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("You're set").font(.title2.weight(.semibold))
            bullet("externaldrive", "Back up your keys and settings with File → Back Up… (⇧⌘B).")
            bullet("checkmark.shield", "Security → Audit shows what to fix; Security → Commit Signing sets up git.")
            bullet("questionmark.circle", "You can see this introduction again in Settings → General.")
        }
    }

    private func bullet(_ symbol: String, _ text: String) -> some View {
        Label {
            Text(text)
        } icon: {
            Image(systemName: symbol).foregroundStyle(.tint)
        }
    }
}

/// Minutes of inactivity before the app lock engages.
struct IdleLockPicker: View {
    @Binding var settings: AppLockSettings

    var body: some View {
        Picker("Lock after", selection: $settings.idleMinutes) {
            ForEach(AppLockSettings.idleChoices, id: \.self) { minutes in
                switch minutes {
                case 0: Text("Only at launch and screen lock").tag(0)
                case 60: Text("1 hour idle").tag(60)
                case 1: Text("1 minute idle").tag(1)
                default: Text("\(minutes) minutes idle").tag(minutes)
                }
            }
        }
    }
}
