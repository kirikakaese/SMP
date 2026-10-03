import Foundation
import SMPCore
import SMPSSH

/// Bitbucket Cloud (API 2.0). API tokens authenticate with HTTP Basic: account email + token.
struct BitbucketClient: ProviderClient {
    private let api: ProviderAPI
    private let account: ProviderAccount

    init(account: ProviderAccount, token: String, transport: any HTTPTransport) throws {
        self.account = account
        guard let email = account.loginEmail?.trimmingCharacters(in: .whitespaces), !email.isEmpty,
              !email.contains(":")
        else {
            throw SMPError.invalidArgument("Bitbucket needs the email address of your Atlassian account.")
        }
        let credentials = Data("\(email):\(token)".utf8).base64EncodedString()
        api = try ProviderAPI(
            kind: .bitbucket,
            baseURL: URL(string: "https://api.bitbucket.org/2.0") ?? account.serverURL,
            authorization: "Basic \(credentials)",
            transport: transport
        )
    }

    private struct User: Decodable {
        let username: String?
        let uuid: String
    }

    private struct Key: Decodable {
        let uuid: String
        let key: String
        let label: String?
        let comment: String?
        let createdOn: String?
        let lastUsed: String?
    }

    private struct Page: Decodable {
        let values: [Key]
        let next: String?
    }

    private func user() async throws -> User {
        try await api.get(User.self, api.url("user")).0
    }

    func currentUsername() async throws -> String {
        let user = try await user()
        return user.username ?? user.uuid
    }

    func listKeys() async throws -> [RemoteKey] {
        let owner = try await user().uuid
        var keys: [RemoteKey] = []
        var next: URL? = api.url("users/\(owner)/ssh-keys", query: [URLQueryItem(name: "pagelen", value: "100")])
        var pages = 0
        while let url = next, pages < ProviderAPI.maxPages {
            let page = try await api.get(Page.self, url).0
            keys += page.values.map(remoteKey)
            next = page.next.flatMap(URL.init(string:))
            pages += 1
        }
        return keys
    }

    private func remoteKey(_ key: Key) -> RemoteKey {
        RemoteKey.parsed(
            remoteID: key.uuid, account: account, title: key.label ?? key.comment, key: key.key,
            usages: [.authentication], createdAt: key.createdOn, lastUsedAt: key.lastUsed
        )
    }

    func addKey(title: String, publicKey: SSHPublicKey, usages: Set<RemoteKeyUsage>) async throws -> [RemoteKey] {
        try requireSupported(usages, by: .bitbucket)
        let owner = try await user().uuid
        let (data, _) = try await api.send("POST", api.url("users/\(owner)/ssh-keys"), json: [
            "label": title, "key": publicKey.uploadLine,
        ])
        return [remoteKey(try api.decode(Key.self, from: data))]
    }

    func deleteKey(_ key: RemoteKey) async throws {
        let owner = try await user().uuid
        try await api.send("DELETE", api.url("users/\(owner)/ssh-keys/\(key.remoteID)"))
    }
}
