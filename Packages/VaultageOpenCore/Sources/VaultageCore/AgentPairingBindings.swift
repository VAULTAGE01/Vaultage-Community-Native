import Foundation
import Security

// BL-136 step 3 (D70 amendment 2) — the pairing binding.
//
// One Keychain item per paired agent, in the **broker-only** access group
// (audit H-07): the app process cannot read or write it, and no same-user
// process outside this team's signed binaries can either. It maps the origin's
// digest to the client id. `metadata.json` keeps only the display record, so a
// row written into the file by anything but the broker identifies nothing —
// resolution at connect is origin → digest → *this* binding → active record.
//
// The design review's S6: `AfterFirstUnlockThisDeviceOnly` (the broker runs
// unattended after login and the binding is not a secret), never
// synchronizable, add-only (a bound digest is never overwritten; re-pairing
// after a revoke mints a new record under a new binding), and a versioned
// account name so a later shape takes a new prefix rather than a migration.

/// The binding store. A protocol so the ceremony's contracts run without a
/// Keychain, against `InMemoryAgentBindings`.
public protocol AgentBindingStoring: Sendable {
    /// The client id bound to this origin digest, or nil.
    func clientID(forDigest digest: String) throws -> UUID?
    /// Binds a digest to a client id. Add-only: a digest that is already bound
    /// is refused, never replaced.
    func bind(digest: String, clientID: UUID) throws
    /// Removes one binding. An absent binding is a completed step.
    func unbind(digest: String) throws
}

/// The test store: the same rules, in memory.
public final class InMemoryAgentBindings: AgentBindingStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var rows: [String: UUID] = [:]

    public init() {}

    public func clientID(forDigest digest: String) throws -> UUID? {
        lock.lock(); defer { lock.unlock() }
        return rows[digest]
    }

    public func bind(digest: String, clientID: UUID) throws {
        lock.lock(); defer { lock.unlock() }
        guard rows[digest] == nil else { throw VaultageError.policyDenied("This agent is already paired.") }
        rows[digest] = clientID
    }

    public func unbind(digest: String) throws {
        lock.lock(); defer { lock.unlock() }
        rows[digest] = nil
    }

    /// Test-visible: how many bindings exist.
    public var count: Int { lock.lock(); defer { lock.unlock() }; return rows.count }
}

/// The shipping store, in the broker-only Keychain access group.
public struct KeychainAgentBindings: AgentBindingStoring {
    /// The account prefix; the digest follows. Versioned (S6).
    public static let accountPrefix = "agent-pairing.v1."

    private let service: String
    private let accessGroupDecision: KeychainAccessGroup.LaunchDecision

    public init(service: String = KeychainVault.service, accessGroupDecision: KeychainAccessGroup.LaunchDecision = KeychainAccessGroup.current) {
        self.service = service
        self.accessGroupDecision = accessGroupDecision
    }

    private func account(_ digest: String) -> String { Self.accountPrefix + digest }

    public func clientID(forDigest digest: String) throws -> UUID? {
        let query = KeychainAccessGroup.readAttributes(service: service, account: account(digest), accessGroup: try KeychainAccessGroup.resolvedForBrokerOnly(accessGroupDecision))
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data, data.count == 16 else { throw VaultageError.storage("A pairing binding is not a client id.") }
            return UUID(uuid: data.withUnsafeBytes { $0.load(as: uuid_t.self) })
        case errSecItemNotFound:
            return nil
        default:
            throw VaultageError.storage("The pairing binding could not be read (\(status)).")
        }
    }

    public func bind(digest: String, clientID: UUID) throws {
        var add = KeychainAccessGroup.saveAttributes(service: service, account: account(digest), accessGroup: try KeychainAccessGroup.resolvedForBrokerOnly(accessGroupDecision))
        add[kSecValueData as String] = withUnsafeBytes(of: clientID.uuid) { Data($0) }
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        add[kSecAttrSynchronizable as String] = false
        let status = SecItemAdd(add as CFDictionary, nil)
        switch status {
        case errSecSuccess: return
        case errSecDuplicateItem: throw VaultageError.policyDenied("This agent is already paired.")
        default: throw VaultageError.storage("The pairing could not be recorded (\(status)).")
        }
    }

    public func unbind(digest: String) throws {
        let query = KeychainAccessGroup.deleteAttributes(service: service, account: account(digest), accessGroup: try KeychainAccessGroup.resolvedForBrokerOnly(accessGroupDecision))
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw VaultageError.storage("The pairing could not be removed (\(status)).")
        }
    }
}
