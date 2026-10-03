import Foundation
import SMPCore
import SMPSSH

/// GitLab.com and self-managed GitLab (REST API v4).
struct GitLabClient: ProviderClient {
    private let api: ProviderAPI
    private let account: ProviderAccount

    init(account: ProviderAccount, token: String, transport: any HTTPTransport) throws {
        self.account = account
        api = try ProviderAPI(
            kind: .gitlab,
            baseURL: account.serverURL.appending(path: "api/v4"),
            authorization: "Bearer \(token)",
            transport: transport
        )
    }

    private struct User: Decodable { let username: String }

    private struct Key: Decodable {
        let id: Int
        let title: String?
        let key: String
        let createdAt: String?
        let expiresAt: String?
        let lastUsedAt: String?
        let usageType: String?
    }

    func currentUsername() async throws -> String {
        try await api.get(User.self, api.url("user")).0.username
    }

    func listKeys() async throws -> [RemoteKey] {
        var keys: [RemoteKey] = []
        var page = 1
        while page <= ProviderAPI.maxPages {
            let url = api.url("user/keys", query: [
                URLQueryItem(name: "per_page", value: "100"), URLQueryItem(name: "page", value: String(page)),
            ])
            let (batch, response) = try await api.get([Key].self, url)
            keys += batch.map(remoteKey)
            guard let next = response.value(forHTTPHeaderField: "X-Next-Page"), let number = Int(next) else { break }
            page = number
        }
        return keys
    }

    private func remoteKey(_ key: Key) -> RemoteKey {
        RemoteKey.parsed(
            remoteID: String(key.id), account: account, title: key.title, key: key.key,
            usages: Self.usages(key.usageType), createdAt: key.createdAt,
            lastUsedAt: key.lastUsedAt, expiresAt: key.expiresAt
        )
    }

    /// GitLab versions before 15.7 do not report a usage type; their keys are for authentication.
    static func usages(_ usageType: String?) -> Set<RemoteKeyUsage> {
        switch usageType {
        case "signing": [.signing]
        case "auth_and_signing": [.authentication, .signing]
        default: [.authentication]
        }
    }

    static func usageType(_ usages: Set<RemoteKeyUsage>) -> String {
        switch (usages.contains(.authentication), usages.contains(.signing)) {
        case (true, true): "auth_and_signing"
        case (false, true): "signing"
        default: "auth"
        }
    }

    func addKey(title: String, publicKey: SSHPublicKey, usages: Set<RemoteKeyUsage>) async throws -> [RemoteKey] {
        try requireSupported(usages, by: .gitlab)
        let (data, _) = try await api.send("POST", api.url("user/keys"), json: [
            "title": title, "key": publicKey.uploadLine, "usage_type": Self.usageType(usages),
        ])
        return [remoteKey(try api.decode(Key.self, from: data))]
    }

    func deleteKey(_ key: RemoteKey) async throws {
        try await api.send("DELETE", api.url("user/keys/\(key.remoteID)"))
    }
}
