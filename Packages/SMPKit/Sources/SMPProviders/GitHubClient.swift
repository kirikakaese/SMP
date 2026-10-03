import Foundation
import SMPCore
import SMPSSH

/// GitHub and GitHub Enterprise Server (REST API v3).
struct GitHubClient: ProviderClient {
    private let api: ProviderAPI
    private let account: ProviderAccount

    init(account: ProviderAccount, token: String, transport: any HTTPTransport) throws {
        self.account = account
        let host = account.serverURL.host()?.lowercased()
        let base = host == "github.com"
            ? URL(string: "https://api.github.com") ?? account.serverURL
            : account.serverURL.appending(path: "api/v3")
        api = try ProviderAPI(
            kind: .github,
            baseURL: base,
            authorization: "Bearer \(token)",
            headers: ["Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"],
            transport: transport
        )
    }

    private struct User: Decodable { let login: String }

    private struct Key: Decodable {
        let id: Int
        let key: String
        let title: String?
        let createdAt: String?
        let lastUsed: String?
    }

    func currentUsername() async throws -> String {
        try await api.get(User.self, api.url("user")).0.login
    }

    func listKeys() async throws -> [RemoteKey] {
        let authentication = try await list("user/keys", usage: .authentication)
        let signing = try await list("user/ssh_signing_keys", usage: .signing)
        return authentication + signing
    }

    private func list(_ path: String, usage: RemoteKeyUsage) async throws -> [RemoteKey] {
        var keys: [RemoteKey] = []
        var next: URL? = api.url(path, query: [URLQueryItem(name: "per_page", value: "100")])
        var pages = 0
        while let url = next, pages < ProviderAPI.maxPages {
            let (page, response) = try await api.get([Key].self, url)
            keys += page.map(remoteKey(usage: usage))
            next = ProviderAPI.nextLink(in: response)
            pages += 1
        }
        return keys
    }

    private func remoteKey(usage: RemoteKeyUsage) -> (Key) -> RemoteKey {
        { key in
            RemoteKey.parsed(
                remoteID: String(key.id), account: account, title: key.title, key: key.key,
                usages: [usage], createdAt: key.createdAt, lastUsedAt: key.lastUsed
            )
        }
    }

    func addKey(title: String, publicKey: SSHPublicKey, usages: Set<RemoteKeyUsage>) async throws -> [RemoteKey] {
        try requireSupported(usages, by: .github)
        var added: [RemoteKey] = []
        for usage in usages.sorted(by: { $0.rawValue < $1.rawValue }) {
            let path = usage == .signing ? "user/ssh_signing_keys" : "user/keys"
            let (data, _) = try await api.send(
                "POST", api.url(path), json: ["title": title, "key": publicKey.uploadLine]
            )
            added.append(remoteKey(usage: usage)(try api.decode(Key.self, from: data)))
        }
        return added
    }

    func deleteKey(_ key: RemoteKey) async throws {
        let path = key.usages.contains(.signing) ? "user/ssh_signing_keys" : "user/keys"
        try await api.send("DELETE", api.url("\(path)/\(key.remoteID)"))
    }
}
