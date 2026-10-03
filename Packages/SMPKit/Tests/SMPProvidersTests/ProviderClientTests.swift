import Foundation
import SMPCore
import SMPSSH
import SMPTestFixtures
import Testing

@testable import SMPProviders

/// Answers requests from a table of `METHOD path?query` → response, and records every request.
final class FakeTransport: HTTPTransport, @unchecked Sendable {
    struct Reply {
        var status = 200
        var body = "{}"
        var headers: [String: String] = [:]
    }

    private let lock = NSLock()
    private let replies: [String: Reply]
    private var sent: [URLRequest] = []

    init(_ replies: [String: Reply]) {
        self.replies = replies
    }

    var requests: [URLRequest] { lock.withLock { sent } }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let url = try #require(request.url)
        let query = url.query(percentEncoded: true).map { "?" + $0 } ?? ""
        let key = "\(request.httpMethod ?? "GET") \(url.path(percentEncoded: true))\(query)"
        lock.withLock { sent.append(request) }
        guard let reply = replies[key] else {
            Issue.record("Unexpected request: \(key)")
            throw SMPError(.network, whatHappened: "No fake reply for \(key)")
        }
        let response = try #require(HTTPURLResponse(
            url: url, statusCode: reply.status, httpVersion: "HTTP/1.1", headerFields: reply.headers
        ))
        return (Data(reply.body.utf8), response)
    }
}

// MARK: Helpers

private let token = SecureBytes(utf8: "test-token-123")

private func server(_ text: String) -> URL {
    URLComponents(string: text)?.url ?? URL(filePath: "/invalid")
}

/// `type base64` of a fixture line (providers usually drop the comment).
private func keyBase(_ line: String) -> String {
    line.split(separator: " ").prefix(2).joined(separator: " ")
}

private func json(_ object: [String: Any]) -> String {
    encode(object)
}

private func json(_ object: [[String: Any]]) -> String {
    encode(object)
}

private func encode(_ object: Any) -> String {
    let data = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
    return String(decoding: data, as: UTF8.self)
}

private func body(of request: URLRequest?) throws -> [String: String] {
    let data = try #require(request?.httpBody)
    return try #require(try JSONSerialization.jsonObject(with: data) as? [String: String])
}

private func client(_ account: ProviderAccount, _ transport: FakeTransport) throws -> any ProviderClient {
    try ProviderClientFactory(transport: transport).client(for: account, token: token)
}

private func ed25519() throws -> SSHPublicKey {
    try SSHPublicKey(line: Fixtures.ed25519Public)
}

// MARK: GitHub

@Suite("GitHub client")
struct GitHubClientTests {
    let account = ProviderAccount(kind: .github, serverURL: server("https://github.com"), username: "alice")

    @Test func listsAuthenticationAndSigningKeysAcrossPages() async throws {
        let page2 = "https://api.github.com/user/keys?per_page=100&page=2"
        let transport = FakeTransport([
            "GET /user/keys?per_page=100": .init(
                body: json([[
                    "id": 1, "key": keyBase(Fixtures.ed25519Public), "title": "laptop",
                    "created_at": "2024-01-02T03:04:05Z",
                ]]),
                headers: ["Link": "<\(page2)>; rel=\"next\", <\(page2)>; rel=\"last\""]
            ),
            "GET /user/keys?per_page=100&page=2": .init(
                body: json([["id": 2, "key": keyBase(Fixtures.rsa3072Public), "title": "old"]])
            ),
            "GET /user/ssh_signing_keys?per_page=100": .init(
                body: json([["id": 9, "key": keyBase(Fixtures.ed25519Public), "title": "signing"]])
            ),
        ])
        let keys = try await client(account, transport).listKeys()
        #expect(keys.map(\.remoteID) == ["1", "2", "9"])
        #expect(keys.map(\.usages) == [[.authentication], [.authentication], [.signing]])
        let expected = try ed25519().fingerprintSHA256
        #expect(keys[0].fingerprint == expected)
        #expect(keys[0].createdAt == Date(timeIntervalSince1970: 1_704_164_645))
        #expect(Set(keys.map(\.id)).count == 3)

        let first = try #require(transport.requests.first)
        #expect(first.value(forHTTPHeaderField: "Authorization") == "Bearer test-token-123")
        #expect(first.value(forHTTPHeaderField: "X-GitHub-Api-Version") == "2022-11-28")
        #expect(first.url?.host() == "api.github.com")
    }

    @Test func uploadsWithoutTheLocalCommentAndDeletesFromTheRightList() async throws {
        let key = keyBase(Fixtures.ed25519Public)
        let transport = FakeTransport([
            "POST /user/keys": .init(status: 201, body: json(["id": 5, "key": key, "title": "Mac"])),
            "POST /user/ssh_signing_keys": .init(status: 201, body: json(["id": 6, "key": key, "title": "Mac"])),
            "DELETE /user/ssh_signing_keys/6": .init(status: 204, body: ""),
        ])
        let github = try client(account, transport)
        let added = try await github.addKey(title: "Mac", publicKey: try ed25519(), usages: [.authentication, .signing])
        #expect(added.map(\.usages) == [[.authentication], [.signing]])
        #expect(added.last?.remoteID == "6")
        let posted = try body(of: transport.requests.first)
        #expect(posted == ["title": "Mac", "key": keyBase(Fixtures.ed25519Public)])
        #expect(!(posted["key"] ?? "").contains("alice@example.com"))

        try await github.deleteKey(try #require(added.last))
        #expect(transport.requests.last?.httpMethod == "DELETE")
        #expect(transport.requests.last?.url?.path() == "/user/ssh_signing_keys/6")
    }

    @Test func usesTheEnterpriseAPIPath() async throws {
        let enterprise = ProviderAccount(kind: .github, serverURL: server("https://ghe.example.com"), username: "")
        let transport = FakeTransport(["GET /api/v3/user": .init(body: json(["login": "bob"]))])
        #expect(try await client(enterprise, transport).currentUsername() == "bob")
    }

    @Test func mapsErrors() async throws {
        let transport = FakeTransport([
            "GET /user": .init(status: 401, body: json(["message": "Bad credentials"])),
            "POST /user/keys": .init(
                status: 422,
                body: json(["message": "Validation Failed", "errors": [["message": "key is already in use"]]])
            ),
            "GET /user/keys?per_page=100": .init(
                status: 403, body: json(["message": "API rate limit exceeded"]),
                headers: ["X-RateLimit-Remaining": "0"]
            ),
        ])
        let github = try client(account, transport)
        let unauthorized = await #expect(throws: SMPError.self) { _ = try await github.currentUsername() }
        #expect(unauthorized?.whatHappened == "GitHub rejected the token.")
        #expect(unauthorized?.details == "Bad credentials")
        let duplicate = await #expect(throws: SMPError.self) {
            _ = try await github.addKey(title: "x", publicKey: try ed25519(), usages: [.authentication])
        }
        #expect(duplicate?.code == .alreadyExists)
        let limited = await #expect(throws: SMPError.self) { _ = try await github.listKeys() }
        #expect(limited?.whatHappened.contains("limiting") == true)
    }
}

// MARK: GitLab

@Suite("GitLab client")
struct GitLabClientTests {
    let account = ProviderAccount(
        kind: .gitlab, serverURL: server("https://gitlab.example.com/gitlab"), username: "alice"
    )

    @Test func readsUsageTypesAndFollowsPages() async throws {
        let transport = FakeTransport([
            "GET /gitlab/api/v4/user/keys?per_page=100&page=1": .init(
                body: json([[
                    "id": 1, "title": "both", "key": keyBase(Fixtures.ed25519Public),
                    "usage_type": "auth_and_signing", "expires_at": "2030-01-01T00:00:00.000Z",
                    "last_used_at": "2024-05-01T10:00:00.123Z",
                ]]),
                headers: ["X-Next-Page": "2"]
            ),
            "GET /gitlab/api/v4/user/keys?per_page=100&page=2": .init(
                body: json([["id": 2, "title": "legacy", "key": keyBase(Fixtures.rsa3072Public)]]),
                headers: ["X-Next-Page": ""]
            ),
        ])
        let keys = try await client(account, transport).listKeys()
        #expect(keys.map(\.usages) == [[.authentication, .signing], [.authentication]])
        #expect(keys[0].expiresAt != nil)
        #expect(keys[0].lastUsedAt != nil)
        #expect(transport.requests.first?.value(forHTTPHeaderField: "Authorization") == "Bearer test-token-123")
    }

    @Test func sendsTheUsageTypeWhenUploading() async throws {
        let reply = json(["id": 3, "title": "Mac", "key": keyBase(Fixtures.ed25519Public), "usage_type": "signing"])
        let transport = FakeTransport(["POST /gitlab/api/v4/user/keys": .init(status: 201, body: reply)])
        let gitlab = try client(account, transport)
        let added = try await gitlab.addKey(title: "Mac", publicKey: try ed25519(), usages: [.signing])
        #expect(added.first?.usages == [.signing])
        #expect(try body(of: transport.requests.first)["usage_type"] == "signing")
        #expect(GitLabClient.usageType([.authentication]) == "auth")
        #expect(GitLabClient.usageType([.authentication, .signing]) == "auth_and_signing")
    }
}

// MARK: Gitea and Bitbucket

@Suite("Gitea and Bitbucket clients")
struct GiteaBitbucketClientTests {
    @Test func giteaPagesUntilAShortPage() async throws {
        let account = ProviderAccount(kind: .gitea, serverURL: server("https://git.example.com"), username: "alice")
        let full: [[String: Any]] = (1...50).map {
            ["id": $0, "key": keyBase(Fixtures.ed25519Public), "title": "k\($0)"]
        }
        let transport = FakeTransport([
            "GET /api/v1/user/keys?limit=50&page=1": .init(body: json(full)),
            "GET /api/v1/user/keys?limit=50&page=2": .init(
                body: json([["id": 51, "key": keyBase(Fixtures.rsa3072Public), "title": "last"]])
            ),
        ])
        let gitea = try client(account, transport)
        #expect(try await gitea.listKeys().count == 51)
        #expect(transport.requests.first?.value(forHTTPHeaderField: "Authorization") == "token test-token-123")
        await #expect(throws: SMPError.self) {
            _ = try await gitea.addKey(title: "x", publicKey: try ed25519(), usages: [.signing])
        }
    }

    @Test func bitbucketUsesBasicAuthAndTheUserUUID() async throws {
        let account = ProviderAccount(
            kind: .bitbucket, serverURL: server("https://bitbucket.org"), username: "alice",
            loginEmail: "alice@example.com"
        )
        let keys = "/2.0/users/%7B1234%7D/ssh-keys"
        let transport = FakeTransport([
            "GET /2.0/user": .init(body: json(["username": "alice", "uuid": "{1234}"])),
            "GET \(keys)?pagelen=100": .init(body: json([
                "values": [[
                    "uuid": "{k1}", "key": Fixtures.ed25519Public, "label": "laptop",
                    "created_on": "2018-03-14T13:17:05.196003+00:00",
                ]],
                "next": "https://api.bitbucket.org\(keys)?pagelen=100&page=2",
            ])),
            "GET \(keys)?pagelen=100&page=2": .init(body: json(["values": [] as [Any]])),
            "DELETE \(keys)/%7Bk1%7D": .init(status: 204, body: ""),
        ])
        let bitbucket = try client(account, transport)
        let listed = try await bitbucket.listKeys()
        #expect(listed.map(\.title) == ["laptop"])
        #expect(listed.first?.createdAt != nil)
        let expected = "Basic " + Data("alice@example.com:test-token-123".utf8).base64EncodedString()
        #expect(transport.requests.first?.value(forHTTPHeaderField: "Authorization") == expected)
        try await bitbucket.deleteKey(try #require(listed.first))
        #expect(transport.requests.last?.httpMethod == "DELETE")
    }
}

// MARK: Safety

@Suite("Provider HTTP safety")
struct ProviderHTTPTests {
    @Test func refusesPlainHTTPAndForeignPaginationLinks() async throws {
        let insecure = ProviderAccount(kind: .gitea, serverURL: server("http://git.example.com"), username: "")
        #expect(throws: SMPError.self) { _ = try client(insecure, FakeTransport([:])) }

        let account = ProviderAccount(kind: .github, serverURL: server("https://github.com"), username: "alice")
        let transport = FakeTransport([
            "GET /user/keys?per_page=100": .init(
                body: "[]", headers: ["Link": "<https://evil.example.com/x>; rel=\"next\""]
            ),
        ])
        await #expect(throws: SMPError.self) { _ = try await client(account, transport).listKeys() }
        #expect(transport.requests.allSatisfy { $0.url?.host() == "api.github.com" })
    }

    @Test func rejectsTokensWithSpaces() {
        let account = ProviderAccount(kind: .github, serverURL: server("https://github.com"), username: "")
        let factory = ProviderClientFactory(transport: FakeTransport([:]))
        #expect(throws: SMPError.self) { _ = try factory.client(for: account, token: SecureBytes(utf8: "a b")) }
    }

    @Test func parsesProviderDates() {
        #expect(ProviderDate.parse("2024-01-02T03:04:05Z") == Date(timeIntervalSince1970: 1_704_164_645))
        #expect(ProviderDate.parse("2024-01-02T03:04:05.123Z") != nil)
        #expect(ProviderDate.parse("2018-03-14T13:17:05.196003+00:00") != nil)
        #expect(ProviderDate.parse("not a date") == nil)
        #expect(ProviderDate.parse(nil) == nil)
    }

    @Test func extractsServerMessagesWithoutRequestData() {
        let gitlab = Data(json(["message": ["key": ["has already been taken"]]]).utf8)
        #expect(ProviderAPI.serverMessage(in: gitlab)?.contains("has already been taken") == true)
        #expect(ProviderAPI.serverMessage(in: Data(json(["error": ["message": "Bad token"]]).utf8)) == "Bad token")
        #expect(ProviderAPI.serverMessage(in: Data()) == nil)
    }
}
