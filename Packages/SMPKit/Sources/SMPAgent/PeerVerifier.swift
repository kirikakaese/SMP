import Foundation
import SMPCore
import Security

/// Decides which local processes may create, change and delete Secure Enclave keys through the
/// agent. Listing identities and signing stay open to every process of the user, as with any agent.
public protocol PeerVerifying: Sendable {
    func mayManageKeys(_ peer: PeerProcess) -> Bool
}

/// Always gives the same answer. For tests.
public struct FixedPeerVerifier: PeerVerifying {
    private let allows: Bool

    public init(allows: Bool) {
        self.allows = allows
    }

    public func mayManageKeys(_ peer: PeerProcess) -> Bool { allows }
}

/// Allows only the SMP app that contains this agent helper: the peer's code signature must be
/// valid and its bundle must be the app at `SMP.app`, where the helper lives in
/// `Contents/Library/LoginItems`. When the helper is signed by a team, the peer must also be
/// signed by that team with SMP's bundle identifier.
public struct CodeSignaturePeerVerifier: PeerVerifying {
    private let appURL: URL
    private let requirement: String?

    /// - Returns: `nil` when the helper does not run from inside an app bundle (e.g. in tests).
    public init?(helperBundle: Bundle = .main) {
        var url = helperBundle.bundleURL
        for _ in 0..<4 {
            url.deleteLastPathComponent()
        }
        guard url.pathExtension == "app" else { return nil }
        appURL = Self.normalized(url)
        requirement = Self.ownTeamIdentifier().map {
            "identifier \"\(AppPaths.bundleIdentifier)\" and anchor apple generic "
                + "and certificate leaf[subject.OU] = \"\($0)\""
        }
    }

    public func mayManageKeys(_ peer: PeerProcess) -> Bool {
        guard let token = peer.auditToken else { return false }
        var code: SecCode?
        let attributes = [kSecGuestAttributeAudit: token] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, SecCSFlags(), &code) == errSecSuccess,
              let code
        else { return false }
        var parsed: SecRequirement?
        if let requirement,
           SecRequirementCreateWithString(requirement as CFString, SecCSFlags(), &parsed) != errSecSuccess {
            return false
        }
        guard SecCodeCheckValidity(code, SecCSFlags(), parsed) == errSecSuccess else { return false }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess, let staticCode else {
            return false
        }
        var path: CFURL?
        guard SecCodeCopyPath(staticCode, SecCSFlags(), &path) == errSecSuccess, let path else { return false }
        return Self.normalized(path as URL) == appURL
    }

    private static func normalized(_ url: URL) -> URL {
        url.resolvingSymlinksInPath().standardizedFileURL
    }

    /// The team that signed this process, or `nil` for ad-hoc signed builds.
    static func ownTeamIdentifier() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf(SecCSFlags(), &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess, let staticCode else {
            return nil
        }
        var information: CFDictionary?
        let flags = SecCSFlags(rawValue: UInt32(kSecCSSigningInformation))
        guard SecCodeCopySigningInformation(staticCode, flags, &information) == errSecSuccess,
              let values = information as? [String: Any]
        else { return nil }
        return values[kSecCodeInfoTeamIdentifier as String] as? String
    }
}
