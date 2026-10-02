import Foundation

/// The fixed sections of the library sidebar. User-defined tags and groups are added in milestone 2.
public enum SidebarItem: String, Hashable, CaseIterable, Identifiable, Sendable {
    case allKeys
    case favorites
    case secureEnclave
    case hardware
    case loadedInAgent
    case needsAttention
    case archived

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .allKeys: "All Keys"
        case .favorites: "Favorites"
        case .secureEnclave: "Secure Enclave"
        case .hardware: "Hardware (FIDO)"
        case .loadedInAgent: "Loaded in Agent"
        case .needsAttention: "Needs Attention"
        case .archived: "Archived"
        }
    }

    public var systemImage: String {
        switch self {
        case .allKeys: "key"
        case .favorites: "star"
        case .secureEnclave: "lock.shield"
        case .hardware: "cable.connector"
        case .loadedInAgent: "person.badge.key"
        case .needsAttention: "exclamationmark.triangle"
        case .archived: "archivebox"
        }
    }
}
