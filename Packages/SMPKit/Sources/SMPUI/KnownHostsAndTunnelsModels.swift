import Foundation
import Observation
import SMPCore
import SMPServices
import SMPSSH

/// State behind the Known Hosts section.
@MainActor
@Observable
public final class KnownHostsModel {
    public private(set) var loaded: LoadedKnownHosts?
    public var selectedLines: Set<Int> = []
    /// Host name to look up; also matches hashed entries.
    public var searchText = ""
    public var lastError: SMPError?
    public var notice: String?
    /// Sheet requests.
    public var addRequest: HostKeyRequest?
    public var changedKeyRequest: HostKeyRequest?

    @ObservationIgnored let services: ServiceContainer

    public init(services: ServiceContainer) {
        self.services = services
    }

    public var entries: [KnownHostsEntry] { loaded?.entries ?? [] }

    public var visibleEntries: [KnownHostsEntry] {
        let query = searchText.trimmingCharacters(in: .whitespaces)
        guard !query.isEmpty else { return entries }
        let (host, port) = Self.split(query)
        return entries.filter { entry in
            entry.matches(host: host, port: port)
                || entry.hostPatterns.contains { $0.localizedCaseInsensitiveContains(query) }
                || (entry.publicKey?.fingerprintSHA256.contains(query) ?? false)
        }
    }

    public var hashedCount: Int { entries.filter(\.isHashed).count }

    public func reload() {
        do {
            loaded = try services.knownHosts.load()
            selectedLines.formIntersection(entries.map(\.lineIndex))
        } catch {
            lastError = error.asSMPError
        }
    }

    /// Removes entries after the user confirmed. A backup of known_hosts is kept.
    public func remove(lines: Set<Int>) {
        guard let loaded, !lines.isEmpty else { return }
        do {
            try services.knownHosts.remove(lines: lines, from: loaded)
            notice = lines.count == 1 ? "Removed 1 host key." : "Removed \(lines.count) host keys."
            selectedLines = []
            reload()
        } catch {
            lastError = error.asSMPError
            reload()
        }
    }

    public func scan(_ request: HostKeyRequest) async throws -> [SSHPublicKey] {
        try await services.knownHosts.scan(host: request.host, port: request.port)
    }

    public func add(_ keys: [SSHPublicKey], for request: HostKeyRequest) throws {
        try services.knownHosts.add(host: request.host, port: request.port, keys: keys)
        notice = "Added \(keys.count) key(s) for \(request.host)."
        reload()
    }

    public func replace(_ keys: [SSHPublicKey], for request: HostKeyRequest) throws {
        try services.knownHosts.replace(host: request.host, port: request.port, with: keys)
        notice = "Replaced the stored keys for \(request.host)."
        reload()
    }

    public func storedEntries(for request: HostKeyRequest) -> [KnownHostsEntry] {
        entries.filter { $0.matches(host: request.host, port: request.port) }
    }

    /// `host`, `host:port` or `[host]:port`.
    nonisolated static func split(_ text: String) -> (String, Int) {
        var value = text
        if value.hasPrefix("["), let close = value.firstIndex(of: "]") {
            let host = String(value[value.index(after: value.startIndex)..<close])
            let rest = value[value.index(after: close)...]
            return (host, rest.hasPrefix(":") ? Int(rest.dropFirst()) ?? 22 : 22)
        }
        if value.filter({ $0 == ":" }).count == 1, let colon = value.firstIndex(of: ":"),
           let port = Int(value[value.index(after: colon)...]) {
            value = String(value[..<colon])
            return (value, port)
        }
        return (value, 22)
    }
}

/// A host whose keys should be fetched, added or replaced.
public struct HostKeyRequest: Identifiable, Hashable, Sendable {
    public var host: String
    public var port: Int
    public var id: String { "\(host):\(port)" }

    public init(host: String, port: Int = 22) {
        self.host = host
        self.port = port
    }
}

/// State behind the Tunnels section.
@MainActor
@Observable
public final class TunnelsModel {
    public private(set) var tunnels: [TunnelProfile] = []
    public private(set) var states: [UUID: TunnelState] = [:]
    public var selectedTunnelID: UUID?
    public var editing: TunnelProfile?
    public var lastError: SMPError?

    @ObservationIgnored let services: ServiceContainer

    public init(services: ServiceContainer) {
        self.services = services
        services.tunnels.setChangeHandler { [weak self] in
            Task { @MainActor in self?.refreshStates() }
        }
    }

    public func reload() {
        do {
            tunnels = try services.metadata.allTunnels()
            refreshStates()
        } catch {
            lastError = error.asSMPError
        }
    }

    public func refreshStates() {
        states = Dictionary(uniqueKeysWithValues: tunnels.map { ($0.id, services.tunnels.state(of: $0.id)) })
    }

    public func state(of tunnel: TunnelProfile) -> TunnelState { states[tunnel.id] ?? .stopped }

    public func toggle(_ tunnel: TunnelProfile) {
        if state(of: tunnel).isRunning {
            services.tunnels.stop(id: tunnel.id)
        } else {
            do {
                try services.tunnels.start(tunnel)
            } catch {
                lastError = error.asSMPError
            }
        }
        refreshStates()
    }

    public func save(_ tunnel: TunnelProfile) throws {
        _ = try TunnelService.arguments(for: tunnel)
        try services.metadata.saveTunnel(tunnel)
        reload()
        selectedTunnelID = tunnel.id
    }

    public func delete(_ tunnel: TunnelProfile) {
        services.tunnels.stop(id: tunnel.id)
        do {
            try services.metadata.deleteTunnel(id: tunnel.id)
            reload()
        } catch {
            lastError = error.asSMPError
        }
    }

    public func stopAll() {
        services.tunnels.stopAll()
        refreshStates()
    }
}
