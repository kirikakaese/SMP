import Foundation
import SMPCore
import SMPSSH

/// Gitea and Forgejo (API v1).
struct GiteaClient: ProviderClient {
    private let api: ProviderAPI
    private let account: ProviderAccount
    static let pageSize = 50

    init(account: ProviderAccount, token: String, transport: any HTTPTransport) throws {
        self.account = account
        api = try ProviderAPI(
            kind: .gitea,
            baseURL: account.serverURL.appending(path: "api/v1"),
            authorization: "token \(token)",
            transport: transport
        )
    }

    private struct User: Decodable { let login: String }

    private struct Key: Decodable {
        let id: Int
        let key: String
        let title: String?
        let createdAt: String?
    }

    func currentUsername() async throws -> String {
        try await api.get(User.self, api.url("user")).0.login
    }

    func listKeys() async throws -> [RemoteKey] {
        var keys: [RemoteKey] = []
        for page in 1...ProviderAPI.maxPages {
            let url = api.url("user/keys", query: [
                URLQueryItem(name: "limit", value: String(Self.pageSize)),
                URLQueryItem(name: "page", value: String(page)),
            ])
            let batch = try await api.get([Key].self, url).0
            keys += batch.map(remoteKey)
            if batch.count < Self.pageSize { break }
        }
        return keys
    }

    private func remoteKey(_ key: Key) -> RemoteKey {
        RemoteKey.parsed(
            remoteID: String(key.id), account: account, title: key.title, key: key.key,
            usages: [.authentication], createdAt: key.createdAt
        )
    }

    func addKey(title: String, publicKey: SSHPublicKey, usages: Set<RemoteKeyUsage>) async throws -> [RemoteKey] {
        try requireSupported(usages, by: .gitea)
        let (data, _) = try await api.send("POST", api.url("user/keys"), json: [
            "title": title, "key": publicKey.uploadLine,
        ])
        return [remoteKey(try api.decode(Key.self, from: data))]
    }

    func deleteKey(_ key: RemoteKey) async throws {
        try await api.send("DELETE", api.url("user/keys/\(key.remoteID)"))
    }
}
