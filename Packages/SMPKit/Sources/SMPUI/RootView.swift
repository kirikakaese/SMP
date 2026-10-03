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
    @Environment(\.undoManager) private var undoManager

    public init(
        model: LibraryModel,
        hosts: HostsModel,
        knownHosts: KnownHostsModel,
        tunnels: TunnelsModel,
        agent: AgentModel,
        providers: ProvidersModel
    ) {
        self.model = model
        self.hosts = hosts
        self.knownHosts = knownHosts
        self.tunnels = tunnels
        self.agent = agent
        self.providers = providers
    }

    private var providerAccount: ProviderAccount? {
        if case .provider(let id) = model.sidebarSelection { providers.account(id) } else { nil }
    }

    private var sshSection: SSHSection? {
        if case .ssh(let section) = model.sidebarSelection { section } else { nil }
    }

    public var body: some View {
        NavigationSplitView {
            SidebarView(model: model, providers: providers)
        } content: {
            if let account = providerAccount {
                ProviderKeysView(providers: providers, library: model, account: account)
            } else {
                sshContent
            }
        } detail: {
            if providerAccount != nil {
                RemoteKeyDetailView(providers: providers, library: model)
            } else {
                detail
            }
        }
        .sheet(item: $model.activeSheet) { sheet in
            LibrarySheetHost(model: model, sheet: sheet)
        }
        .overlay(alignment: .bottom) {
            if let notice = model.notice ?? hosts.notice ?? knownHosts.notice ?? providers.notice {
                NoticeBanner(text: notice) {
                    model.notice = nil
                    hosts.notice = nil
                    knownHosts.notice = nil
                    providers.notice = nil
                }
            }
        }
        .dropDestination(for: URL.self) { urls, _ in
            guard let url = urls.first, model.activeSheet == nil, sshSection == nil, providerAccount == nil else {
                return false
            }
            model.activeSheet = .importKey(url)
            return true
        }
        .onChange(of: undoManager, initial: true) { model.windowUndoManager = undoManager }
        .task {
            await model.reload()
            model.startWatching()
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
