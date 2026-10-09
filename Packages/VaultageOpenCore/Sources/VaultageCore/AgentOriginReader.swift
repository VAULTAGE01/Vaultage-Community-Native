import Foundation

// BL-136 step 2 (D70 amendment 2) — who is asking, read from the operating
// system by the broker service and never claimed by the client.
//
// The peer of an XPC connection is the `Vaultage --mcp` process; the agent is
// what launched it — the peer's **parent** — in the folder it was launched
// from. The parent's code signature is asked of Security by pid; an unsigned
// or ad-hoc parent is identified by its executable path only, and a parent
// that cannot be read (launchd, gone, or started after its child, which is the
// shape of a pid reuse) is `unknown` and cannot pair.
//
// Race-safety, as the design review asked (S1): the parent is anchored on its
// pid **and its start time**, taken before the signature read and compared
// again after it, so a parent that exited and had its pid reused mid-read is
// refused rather than described by a stranger's signature.

/// One running host instance: a pid with the start time that makes it this
/// launch and not a later one with the same number. What a per-session arming
/// (step 4) is keyed to.
public struct HostInstance: Hashable, Sendable {
    public let pid: Int32
    public let startSeconds: UInt64
    public let startMicroseconds: UInt64

    public init(pid: Int32, startSeconds: UInt64, startMicroseconds: UInt64) {
        self.pid = pid
        self.startSeconds = startSeconds
        self.startMicroseconds = startMicroseconds
    }
}

/// What the service derived for one connection: the agent's origin (its
/// persistent identity, client × folder) and the running host instance.
public struct AgentConnectionOrigin: Sendable, Hashable {
    public let origin: AgentOrigin
    public let host: HostInstance?

    public init(origin: AgentOrigin, host: HostInstance?) {
        self.origin = origin
        self.host = host
    }

    /// The unknown origin: nothing could be read.
    public static let unknown = AgentConnectionOrigin(origin: AgentOrigin(client: .unknown, folder: nil), host: nil)
}

#if os(macOS)
import Darwin
import Security

public enum AgentOriginReader {
    /// Derives the origin for the process that opened a connection.
    public static func read(peer pid: Int32) -> AgentConnectionOrigin {
        guard pid > 1, let child = bsdInfo(pid) else { return .unknown }
        let ppid = Int32(child.pbi_ppid)
        // launchd, or no parent: nothing launched this in any useful sense.
        guard ppid > 1, let parent = bsdInfo(ppid) else { return .unknown }
        // A parent that started after its child is a reused pid, not a parent.
        guard (parent.pbi_start_tvsec, parent.pbi_start_tvusec) <= (child.pbi_start_tvsec, child.pbi_start_tvusec) else { return .unknown }
        let host = HostInstance(pid: ppid, startSeconds: parent.pbi_start_tvsec, startMicroseconds: parent.pbi_start_tvusec)
        let folder = currentDirectory(ppid)
        let client: AgentClient
        if let signed = signature(ppid) {
            client = signed
        } else if let path = executablePath(ppid) {
            client = .unsigned(path: path)
        } else {
            client = .unknown
        }
        // S1: the parent is the same launch after the signature read as before it.
        guard isRunning(host) else { return .unknown }
        return AgentConnectionOrigin(origin: AgentOrigin(client: client, folder: folder), host: host)
    }

    /// Whether this exact launch is still running — the pid with the start
    /// time it had. Re-checked at each auto-allow decision (S1), so an arming
    /// keyed to a host does not outlive the host.
    public static func isRunning(_ host: HostInstance) -> Bool {
        guard let info = bsdInfo(host.pid) else { return false }
        return info.pbi_start_tvsec == host.startSeconds && info.pbi_start_tvusec == host.startMicroseconds
    }

    private static func bsdInfo(_ pid: Int32) -> proc_bsdinfo? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        let got = withUnsafeMutablePointer(to: &info) { proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, $0, size) }
        return got == size ? info : nil
    }

    private static func currentDirectory(_ pid: Int32) -> String? {
        var info = proc_vnodepathinfo()
        let size = Int32(MemoryLayout<proc_vnodepathinfo>.size)
        let got = withUnsafeMutablePointer(to: &info) { proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, $0, size) }
        guard got == size else { return nil }
        let path = withUnsafePointer(to: &info.pvi_cdir.vip_path) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
        }
        return path.isEmpty ? nil : path
    }

    private static func executablePath(_ pid: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN)) // PROC_PIDPATHINFO_MAXSIZE
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }
        return String(cString: buffer)
    }

    /// The parent's valid, non-ad-hoc signature with a team identifier, or nil.
    private static func signature(_ pid: Int32) -> AgentClient? {
        var code: SecCode?
        let attributes = [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code else { return nil }
        guard SecCodeCheckValidity(code, [], nil) == errSecSuccess else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let dictionary = information as? [String: Any] else { return nil }
        // kSecCodeSignatureAdhoc: an ad-hoc signature names no team and proves
        // nothing about who built the binary.
        if let flags = dictionary[kSecCodeInfoFlags as String] as? UInt32, flags & 0x2 != 0 { return nil }
        guard let team = dictionary[kSecCodeInfoTeamIdentifier as String] as? String,
              let identifier = dictionary[kSecCodeInfoIdentifier as String] as? String else { return nil }
        return .signed(teamID: team, identifier: identifier)
    }
}
#else
public enum AgentOriginReader {
    public static func read(peer pid: Int32) -> AgentConnectionOrigin { .unknown }
    public static func isRunning(_ host: HostInstance) -> Bool { false }
}
#endif
