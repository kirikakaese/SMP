import SMPCore
import SwiftUI

/// The main window: sidebar / list / detail. The list and detail columns follow the sidebar section.
public struct RootView: View {
    @Bindable private var model: LibraryModel
    @Bindable private var hosts: HostsModel
    @Bindable private var knownHosts: KnownHostsModel
    @Bindable private var tunnels: TunnelsModel
    @Bindable private var agent: AgentModel
    @Bindable private var providers: ProvidersModel
    @Bindable private var security: SecurityModel
    @Bindable private var appLock: AppLockModel
    @Environment(\.undoManager) private var undoManager
    @State private var showsOnboarding = !OnboardingState.isCompleted()

    public init(
        model: LibraryModel,
        hosts: HostsModel,
        knownHosts: KnownHostsModel,
        tunnels: TunnelsModel,
        agent: AgentModel,
        providers: ProvidersModel,
        security: SecurityModel,
        appLock: AppLockModel
    ) {
        self.model = model
        self.hosts = hosts
        self.knownHosts = knownHosts
        self.tunnels = tunnels
        self.agent = agent
        self.providers = providers
        self.security = security
        self.appLock = appLock
    }

    private var providerAccount: ProviderAccount? {
        if case .provider(let id) = model.sidebarSelection { providers.account(id) } else { nil }
    }

    private var securitySection: SecuritySection? {
        if case .security(let section) = model.sidebarSelection { section } else { nil }
    }

    private var sshSection: SSHSection? {
        if case .ssh(let section) = model.sidebarSelection { section } else { nil }
    }

    public var body: some View {
        Group {
            // While locked, the workspace (and every sheet it presents) is removed entirely.
            if appLock.isLocked {
                LockView(model: appLock)
            } else {
                workspace
            }
        }
        .onChange(of: undoManager, initial: true) { model.windowUndoManager = undoManager }
        .task {
            await model.reload()
            model.startWatching()
            security.runAudit(library: model)
        }
        .task {
            // The only automatic network traffic: refresh provider accounts once at launch.
            await providers.refreshAll()
        }
        .errorAlert($model.lastError)
        .errorAlert($hosts.lastError)
        .errorAlert($knownHosts.lastError)
        .errorAlert($tunnels.lastError)
        .errorAlert($agent.lastError)
        .errorAlert($providers.lastError)
        .errorAlert($security.lastError)
    }

    private var workspace: some View {
        NavigationSplitView {
            SidebarView(model: model, providers: providers, security: security)
        } content: {
            if let account = providerAccount {
                ProviderKeysView(providers: providers, library: model, account: account)
            } else if let securitySection {
                switch securitySection {
                case .audit: AuditView(security: security, library: model, hosts: hosts)
                case .signing: SigningView(security: security, library: model, providers: providers)
                }
            } else {
                sshContent
            }
        } detail: {
            if providerAccount != nil {
                RemoteKeyDetailView(providers: providers, library: model)
            } else if let securitySection {
                switch securitySection {
                case .audit: FindingDetailView(security: security, library: model, hosts: hosts)
                case .signing: SigningDetailView()
                }
            } else {
                detail
            }
        }
        .sheet(item: $model.activeSheet) { sheet in
            LibrarySheetHost(model: model, sheet: sheet)
        }
        .overlay(alignment: .bottom) {
            if let notice = model.notice ?? hosts.notice ?? knownHosts.notice ?? providers.notice ?? security.notice {
                NoticeBanner(text: notice) {
                    model.notice = nil
                    hosts.notice = nil
                    knownHosts.notice = nil
                    providers.notice = nil
                    security.notice = nil
                }
            }
        }
        .dropDestination(for: URL.self) { urls, _ in
            let showsKeys = sshSection == nil && providerAccount == nil && securitySection == nil
            guard let url = urls.first, model.activeSheet == nil, showsKeys else {
                return false
            }
            model.activeSheet = .importKey(url)
            return true
        }
        .sheet(isPresented: $showsOnboarding) {
            OnboardingView(library: model, security: security, appLock: appLock, agent: agent) {
                OnboardingState.setCompleted(true)
                showsOnboarding = false
            }
        }
    }

    @ViewBuilder private var sshContent: some View {
        switch sshSection {
        case .hosts: HostListView(model: hosts)
        case .knownHosts: KnownHostsListView(model: knownHosts)
        case .tunnels: TunnelListView(model: tunnels, hosts: hosts)
        case .agent: AgentView(model: agent, hosts: hosts)
        case nil: KeyListView(model: model)
        }
    }

    @ViewBuilder private var detail: some View {
        switch sshSection {
        case .hosts:
            if let host = hosts.selectedHost {
                HostDetailView(model: hosts, library: model, host: host)
                    .id(host.id)
            } else {
                ContentUnavailableView("No Host Selected", systemImage: "server.rack")
            }
        case .knownHosts:
            KnownHostDetailView(model: knownHosts)
        case .tunnels:
            TunnelDetailView(model: tunnels, hosts: hosts)
        case .agent:
            AgentDetailView()
        case nil:
            keyDetail
        }
    }

    @ViewBuilder private var keyDetail: some View {
        if let item = model.selectedItem {
            KeyDetailView(model: model, providers: providers, item: item)
        } else if model.selectedKeyIDs.count > 1 {
            ContentUnavailableView(
                "\(model.selectedKeyIDs.count) Keys Selected",
                systemImage: "key.horizontal"
            )
        } else {
            ContentUnavailableView("No Selection", systemImage: "key", description: Text("Select a key."))
        }
    }
}

extension View {
    /// Shows `error` as an alert with its fix and details, clearing it when dismissed.
    func errorAlert(_ error: Binding<SMPError?>) -> some View {
        alert(
            isPresented: Binding(get: { error.wrappedValue != nil }, set: { if !$0 { error.wrappedValue = nil } }),
            error: error.wrappedValue
        ) { _ in
            Button("OK") { error.wrappedValue = nil }
        } message: { error in
            Text([error.howToFix, error.details].compactMap { $0 }.joined(separator: "\n\n"))
        }
    }
}
