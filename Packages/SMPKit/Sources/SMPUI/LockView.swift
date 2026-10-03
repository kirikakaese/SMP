import SwiftUI

/// Replaces the main window's content while SMP is locked.
struct LockView: View {
    let model: AppLockModel

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.fill")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text("SMP is locked")
                .font(.title2.weight(.semibold))
            Text("Your keys and settings are hidden until you confirm it's you.")
                .foregroundStyle(.secondary)
            Button {
                Task { await model.unlock() }
            } label: {
                Label("Unlock with Touch ID or Password", systemImage: "touchid")
            }
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            .disabled(model.isUnlocking)
            if let message = model.message {
                Text(message).font(.callout).foregroundStyle(.secondary)
            }
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.background)
        // Ask right away; if the user cancels, the button asks again.
        .task { await model.unlock() }
    }
}
