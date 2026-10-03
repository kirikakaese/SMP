import Darwin
import Foundation

/// The local process on the other end of an agent connection, for prompts and the activity log.
public struct PeerProcess: Sendable, Hashable {
    public let pid: pid_t
    public let name: String
    /// The parent's name, which usually says more than "ssh" (e.g. "git").
    public let parentName: String?
    /// The peer's audit token (`LOCAL_PEERTOKEN`), which identifies the process without the
    /// reuse race a bare process ID has. Used to check the peer's code signature.
    public let auditToken: Data?

    public init(pid: pid_t, name: String, parentName: String?, auditToken: Data? = nil) {
        self.pid = pid
        self.name = name
        self.parentName = parentName
        self.auditToken = auditToken
    }

    /// e.g. "git (ssh)" or "ssh".
    public var displayName: String {
        guard let parentName, !parentName.isEmpty, parentName != name else { return name }
        return "\(parentName) (\(name))"
    }

    public static let unknown = PeerProcess(pid: 0, name: "an unknown process", parentName: nil)

    /// Identifies the peer of a connected Unix socket via `LOCAL_PEERPID`.
    static func of(socket fd: Int32) -> PeerProcess {
        var pid: pid_t = 0
        var length = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &length) == 0, pid > 0 else { return .unknown }
        let parent = parentPID(of: pid)
        return PeerProcess(
            pid: pid,
            name: processName(pid) ?? "process \(pid)",
            parentName: parent.flatMap(processName),
            auditToken: auditToken(of: fd)
        )
    }

    /// `LOCAL_PEERTOKEN` from `<sys/un.h>`.
    private static let localPeerToken: Int32 = 0x006

    static func auditToken(of fd: Int32) -> Data? {
        var token = audit_token_t()
        var length = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(fd, SOL_LOCAL, localPeerToken, &token, &length) == 0,
              Int(length) == MemoryLayout<audit_token_t>.size
        else { return nil }
        return withUnsafeBytes(of: token) { Data($0) }
    }

    static func processName(_ pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }
        let bytes = buffer.prefix(Int(length)).map { UInt8(bitPattern: $0) }
        let path = String(decoding: bytes, as: UTF8.self)
        return URL(fileURLWithPath: path).lastPathComponent
    }

    static func parentPID(of pid: pid_t) -> pid_t? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        let parent = pid_t(info.pbi_ppid)
        return parent > 1 ? parent : nil
    }
}
