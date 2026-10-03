import Foundation
import SMPCore

/// Sends HTTP requests. Inject a fake in tests.
public protocol HTTPTransport: Sendable {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

/// `URLSession` with an ephemeral configuration: no cookies, no cache, no credential storage.
/// Redirects are refused so an `Authorization` header can never follow a redirect to another host.
public final class URLSessionTransport: HTTPTransport {
    private let session: URLSession

    public init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.urlCredentialStorage = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 60
        session = URLSession(configuration: configuration)
    }

    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        do {
            let (data, response) = try await session.data(for: request, delegate: NoRedirects())
            guard let http = response as? HTTPURLResponse else {
                throw SMPError(.network, whatHappened: "The server sent an unexpected response.")
            }
            return (data, http)
        } catch let error as SMPError {
            throw error
        } catch {
            throw SMPError(
                .network,
                whatHappened: "SMP could not reach \(request.url?.host() ?? "the server").",
                howToFix: "Check your internet connection and the server address.",
                details: error.localizedDescription
            )
        }
    }

    private final class NoRedirects: NSObject, URLSessionTaskDelegate, Sendable {
        func urlSession(
            _ session: URLSession,
            task: URLSessionTask,
            willPerformHTTPRedirection response: HTTPURLResponse,
            newRequest request: URLRequest
        ) async -> URLRequest? {
            nil
        }
    }
}

/// A JSON API on one provider, with authentication and error mapping.
struct ProviderAPI: Sendable {
    let kind: ProviderKind
    let baseURL: URL
    private let authorization: String
    private let headers: [String: String]
    private let transport: any HTTPTransport

    /// Upper bound for one response; key lists are small.
    static let maxResponseBytes = 4 * 1024 * 1024
    static let maxPages = 20

    /// Providers use snake_case field names.
    static var decoder: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return decoder
    }

    init(
        kind: ProviderKind,
        baseURL: URL,
        authorization: String,
        headers: [String: String] = [:],
        transport: any HTTPTransport
    ) throws {
        guard baseURL.scheme?.lowercased() == "https", baseURL.host() != nil else {
            throw SMPError.invalidArgument("Provider addresses must start with https://.")
        }
        self.kind = kind
        self.baseURL = baseURL
        self.authorization = authorization
        self.headers = headers
        self.transport = transport
    }

    func url(_ path: String, query: [URLQueryItem] = []) -> URL {
        var url = baseURL
        for component in path.split(separator: "/") {
            url.append(path: String(component))
        }
        return query.isEmpty ? url : url.appending(queryItems: query)
    }

    /// Performs a request and returns the body of a 2xx response, or throws a mapped `SMPError`.
    @discardableResult
    func send(
        _ method: String,
        _ url: URL,
        json body: [String: String]? = nil
    ) async throws -> (Data, HTTPURLResponse) {
        // Never follow pagination links to a different server.
        guard url.host() == baseURL.host(), url.scheme == "https" else {
            throw SMPError(.providerRejected, whatHappened: "The provider pointed SMP to a different server.")
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue(authorization, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("SSH-Management-Platform", forHTTPHeaderField: "User-Agent")
        for (name, value) in headers {
            request.setValue(value, forHTTPHeaderField: name)
        }
        if let body {
            request.httpBody = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let (data, response) = try await transport.send(request)
        guard data.count <= Self.maxResponseBytes else {
            throw SMPError(.providerRejected, whatHappened: "The provider sent an unexpectedly large response.")
        }
        guard (200..<300).contains(response.statusCode) else {
            throw Self.error(status: response.statusCode, data: data, response: response, kind: kind)
        }
        return (data, response)
    }

    func get<T: Decodable>(_ type: T.Type, _ url: URL) async throws -> (T, HTTPURLResponse) {
        let (data, response) = try await send("GET", url)
        do {
            return (try Self.decoder.decode(T.self, from: data), response)
        } catch {
            throw SMPError(
                .providerRejected,
                whatHappened: "SMP did not understand the response from \(kind.displayName).",
                details: String(describing: error)
            )
        }
    }

    func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try Self.decoder.decode(T.self, from: data)
        } catch {
            throw SMPError(
                .providerRejected,
                whatHappened: "SMP did not understand the response from \(kind.displayName).",
                details: String(describing: error)
            )
        }
    }

    // MARK: Errors

    static func error(status: Int, data: Data, response: HTTPURLResponse, kind: ProviderKind) -> SMPError {
        let message = serverMessage(in: data)
        let remaining = response.value(forHTTPHeaderField: "X-RateLimit-Remaining")
        if status == 429 || (status == 403 && remaining == "0") {
            return SMPError(
                .providerRejected,
                whatHappened: "\(kind.displayName) is limiting requests right now.",
                howToFix: "Wait a few minutes and try again.",
                details: message
            )
        }
        switch status {
        case 401:
            return SMPError(
                .providerRejected,
                whatHappened: "\(kind.displayName) rejected the token.",
                howToFix: "The token may have expired or been revoked. Create a new one and update the account.",
                details: message
            )
        case 403, 404 where kind == .github:
            return SMPError(
                .providerRejected,
                whatHappened: "The token is not allowed to do this.",
                howToFix: "Create a token with these permissions: \(kind.requiredScopes).",
                details: message
            )
        case 400, 409, 422:
            let lowered = (message ?? "").lowercased()
            let duplicate = lowered.contains("already") || lowered.contains("taken") || lowered.contains("in use")
            return SMPError(
                duplicate ? .alreadyExists : .providerRejected,
                whatHappened: duplicate
                    ? "\(kind.displayName) already has this key (on this or another account)."
                    : "\(kind.displayName) did not accept the request.",
                details: message
            )
        default:
            return SMPError(
                .providerRejected,
                whatHappened: "\(kind.displayName) answered with HTTP \(status).",
                howToFix: status >= 500 ? "The service may be having problems. Try again later." : nil,
                details: message
            )
        }
    }

    /// The human-readable message in a provider's error body, trimmed. Never includes request data.
    static func serverMessage(in data: Data) -> String? {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            let text = String(decoding: data.prefix(300), as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            return text.isEmpty ? nil : text
        }
        var parts: [String] = []
        if let message = object["message"] as? String { parts.append(message) }
        if let errors = object["errors"] as? [[String: Any]] {
            parts += errors.compactMap { $0["message"] as? String }
        }
        if let nested = object["message"] as? [String: Any] {
            parts += nested.values.compactMap { ($0 as? [String])?.joined(separator: ", ") }
        }
        if let error = object["error"] as? [String: Any], let message = error["message"] as? String {
            parts.append(message)
        } else if let error = object["error"] as? String {
            parts.append(error)
        }
        let joined = parts.joined(separator: " ")
        return joined.isEmpty ? nil : String(joined.prefix(300))
    }

    // MARK: Pagination

    /// The `rel="next"` URL of an RFC 8288 `Link` header (GitHub, GitLab).
    static func nextLink(in response: HTTPURLResponse) -> URL? {
        guard let header = response.value(forHTTPHeaderField: "Link") else { return nil }
        for part in header.split(separator: ",") {
            let pieces = part.split(separator: ";").map { $0.trimmingCharacters(in: .whitespaces) }
            guard pieces.count >= 2, pieces.dropFirst().contains("rel=\"next\""),
                  pieces[0].hasPrefix("<"), pieces[0].hasSuffix(">")
            else { continue }
            return URL(string: String(pieces[0].dropFirst().dropLast()))
        }
        return nil
    }
}

/// Parses the date formats providers use (ISO 8601 with or without fractions, any precision).
enum ProviderDate {
    static func parse(_ text: String?) -> Date? {
        guard var text, !text.isEmpty else { return nil }
        // Bitbucket sends microseconds; ISO8601DateFormatter understands at most milliseconds.
        if let dot = text.firstIndex(of: ".") {
            let fractionEnd = text[dot...].dropFirst().firstIndex { !$0.isNumber } ?? text.endIndex
            let digits = text[text.index(after: dot)..<fractionEnd]
            if digits.count > 3 {
                text.replaceSubrange(text.index(after: dot)..<fractionEnd, with: digits.prefix(3))
            }
        }
        let withFractions = ISO8601DateFormatter()
        withFractions.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = withFractions.date(from: text) { return date }
        return ISO8601DateFormatter().date(from: text)
    }
}
