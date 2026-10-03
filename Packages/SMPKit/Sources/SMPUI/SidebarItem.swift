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
        case .allKeys: String(localized: "All Keys")
        case .favorites: String(localized: "Favorites")
        case .secureEnclave: String(localized: "Secure Enclave")
        case .hardware: String(localized: "Hardware (FIDO)")
        case .loadedInAgent: String(localized: "Loaded in Agent")
        case .needsAttention: String(localized: "Needs Attention")
        case .archived: String(localized: "Archived")
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
