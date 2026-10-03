import Foundation
import Observation
import SMPCore
import SMPServices
import SMPSSH

/// State behind the Providers sidebar section and the "On providers" part of key details.
@MainActor
@Observable
public final class ProvidersModel {
    public private(set) var accounts: [ProviderAccount] = []
    public private(set) var keys: [RemoteKey] = []
    public private(set) var refreshing: Set<UUID> = []
    public var selectedKeyID: String?
    public var isAddingAccount = false
    public var lastError: SMPError?
    public var notice: String?

    @ObservationIgnored let services: ServiceContainer
    /// Accounts are refreshed at most this often when their section is opened.
    @ObservationIgnored private let refreshInterval: TimeInterval

    public init(services: ServiceContainer, refreshInterval: TimeInterval = 120) {
        self.services = services
        self.refreshInterval = refreshInterval
    }

    // MARK: Derived

    public func account(_ id: UUID) -> ProviderAccount? {
        accounts.first { $0.id == id }
    }

    public func keys(for account: ProviderAccount) -> [RemoteKey] {
        keys.filter { $0.accountID == account.id }
            .sorted { ($0.createdAt ?? .distantPast) > ($1.createdAt ?? .distantPast) }
    }

    /// Remote keys with the given SHA256 fingerprint, across all accounts.
    public func remoteKeys(matching fingerprint: String?) -> [RemoteKey] {
        guard let fingerprint else { return [] }
        return keys.filter { $0.fingerprint == fingerprint }
    }

    public var selectedKey: RemoteKey? {
        keys.first { $0.id == selectedKeyID }
    }

    // MARK: Loading

    /// Reads accounts and cached keys from the store (no network).
    public func reload() {
        do {
            accounts = try services.providers.accounts()
            keys = try services.providers.cachedKeys()
        } catch {
            lastError = error.asSMPError
        }
    }

    /// Refreshes every account, e.g. on launch. Failures are shown once, not per account.
    public func refreshAll() async {
        reload()
        var failures: [String] = []
        for account in accounts {
            let succeeded = await refresh(account, reportErrors: false)
            if !succeeded {
                failures.append(account.displayName)
            }
        }
        if !failures.isEmpty {
            notice = "Could not refresh \(failures.joined(separator: ", ")). Showing the last known keys."
        }
    }

    /// Refreshes an account unless it was refreshed moments ago.
    public func refreshIfStale(_ account: ProviderAccount) async {
        if let synced = account.lastSyncedAt, Date().timeIntervalSince(synced) < refreshInterval { return }
        await refresh(account)
    }

    @discardableResult
    public func refresh(_ account: ProviderAccount, reportErrors: Bool = true) async -> Bool {
        guard !refreshing.contains(account.id) else { return true }
        refreshing.insert(account.id)
        defer { refreshing.remove(account.id) }
        do {
            _ = try await services.providers.refresh(account)
            reload()
            return true
        } catch {
            if reportErrors {
                lastError = error.asSMPError
            }
            return false
        }
    }

    // MARK: Accounts

    public func addAccount(
        kind: ProviderKind,
        serverURL: URL?,
        loginEmail: String?,
        token: SecureBytes
    ) async throws -> ProviderAccount {
        let account = try await services.providers.addAccount(
            kind: kind, serverURL: serverURL, loginEmail: loginEmail, token: token
        )
        reload()
        await refresh(account)
        notice = "Added \(account.displayName)."
        return account
    }

    public func updateToken(for account: ProviderAccount, token: SecureBytes) async throws {
        try await services.providers.updateToken(for: account, token: token)
        await refresh(account)
        notice = "Updated the token for \(account.displayName)."
    }

    /// Forgets the account in SMP. Keys on the provider are not touched.
    public func removeAccount(_ account: ProviderAccount) {
        do {
            try services.providers.removeAccount(account)
            reload()
            notice = "Removed \(account.displayName) from SMP. Its keys on the provider were not changed."
        } catch {
            lastError = error.asSMPError
        }
    }

    // MARK: Keys

    public func upload(
        _ item: LibraryItem,
        to account: ProviderAccount,
        title: String,
        usages: Set<RemoteKeyUsage>
    ) async throws {
        guard let publicKey = item.key.publicKey else {
            throw SMPError.invalidArgument("“\(item.displayName)” has no public key to upload.")
        }
        _ = try await services.providers.upload(publicKey, title: title, usages: usages, to: account)
        reload()
        notice = "Uploaded “\(item.displayName)” to \(account.displayName)."
    }

    /// Removes a key from the provider after Touch ID or the login password.
    public func delete(_ key: RemoteKey) async {
        guard let account = account(key.accountID) else { return }
        do {
            try await services.authenticator.authenticate(
                reason: "remove the key “\(key.title)” from \(account.displayName)"
            )
            try await services.providers.delete(key, from: account)
            if selectedKeyID == key.id {
                selectedKeyID = nil
            }
            reload()
            notice = "Removed “\(key.title)” from \(account.displayName)."
        } catch {
            lastError = error.asSMPError
        }
    }

    /// `Host` patterns in ~/.ssh/config whose `IdentityFile` points at the local key.
    public func hostsUsing(_ item: LibraryItem) -> [String] {
        let files = [item.key.privateKeyFile?.url, item.key.publicKeyFile?.url].compactMap { $0 }
        guard !files.isEmpty, let references = try? services.config.references(to: files) else { return [] }
        var seen = Set<String>()
        return references.flatMap(\.hostPatterns).filter { seen.insert($0).inserted }
    }
}
