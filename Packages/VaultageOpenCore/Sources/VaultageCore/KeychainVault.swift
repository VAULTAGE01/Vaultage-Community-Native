import Foundation
import Security
import LocalAuthentication

public protocol SecretVault: Sendable {
    func save(_ secret: Data, account: String) throws
    func read(account: String, prompt: String) throws -> VaultSecret
    /// BL-062 follow-up. The same read, told about a presence the human has
    /// **already** proved for this exact account, so the item's `.userPresence`
    /// access control is satisfied by that evaluation instead of raising a
    /// second prompt. See `OwnerAuthentication`.
    ///
    /// Passing `nil`, or an authentication that is expired or bound to another
    /// account, is not an error and is not a bypass: it is exactly the
    /// single-prompt behaviour this seam has always had. Every MCP, broker and
    /// XPC read takes that path.
    func read(account: String, prompt: String, authentication: OwnerAuthentication?) throws -> VaultSecret
    func delete(account: String) throws
}

extension SecretVault {
    /// Vaults that have no notion of a carried presence — every fake in the
    /// self-tests, and any future non-Keychain store — inherit the prompting
    /// read. Only `KeychainVault` overrides it, because only the Keychain is
    /// the thing that was prompting twice.
    public func read(account: String, prompt: String, authentication: OwnerAuthentication?) throws -> VaultSecret {
        try read(account: account, prompt: prompt)
    }
}

public struct KeychainVault: SecretVault {
    /// The one Keychain service every custody item is filed under. Read by
    /// `KeychainGrantSigningKey`, which files its key beside them.
    public static let service = "com.vaultage.foundation20260910.secret"
    private let service = KeychainVault.service
    /// BL-101. The access-group decision for this process, resolved once at
    /// `KeychainAccessGroup.current` and injectable only so the self-tests can
    /// drive the table in `12-REMOTE-APPROVALS-PROTOCOL.md` §11.4.2 without
    /// re-signing a binary. Nothing in the product passes it.
    private let accessGroupDecision: KeychainAccessGroup.LaunchDecision

    public init() { self.init(accessGroupDecision: KeychainAccessGroup.current) }

    public init(accessGroupDecision: KeychainAccessGroup.LaunchDecision) {
        self.accessGroupDecision = accessGroupDecision
    }

    /// Every `SecItem*` call below starts here. A build that must name its
    /// access group and cannot throws before it touches the Keychain, so the
    /// `nil` fallback can never widen where a signed build stores credentials
    /// (DB-M40); an unsigned build gets `nil` and the attribute is omitted,
    /// which is exactly the behaviour before this ticket.
    private func accessGroup() throws -> String? {
        try KeychainAccessGroup.resolvedForCustody(accessGroupDecision)
    }

    public func save(_ secret: Data, account: String) throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .userPresence, &error) else {
            throw VaultageError.storage("Could not create Keychain user-presence control.")
        }
        var query = KeychainAccessGroup.saveAttributes(service: service, account: account, accessGroup: try accessGroup())
        query[kSecValueData as String] = secret
        query[kSecAttrAccessControl as String] = access
        let add = SecItemAdd(query as CFDictionary, nil)
        guard add == errSecSuccess else {
            if add == errSecDuplicateItem {
                throw VaultageError.storage("A protected vault record already exists. Create a new vault item to rotate it safely.")
            }
            throw VaultageError.storage("Could not save protected vault item (\(add)).")
        }
    }

    public func read(account: String, prompt: String) throws -> VaultSecret {
        try read(account: account, prompt: prompt, authentication: nil)
    }

    /// One Keychain read, with at most one OS prompt.
    ///
    /// `authentication` is consulted, never trusted: `keychainContext(for:at:)`
    /// returns a context only when the presence was evaluated, is bound to this
    /// exact `account`, and is inside its 60-second window. Anything else
    /// produces a fresh context and therefore a fresh prompt — the behaviour
    /// before BL-062's follow-up, and the behaviour every agent-facing caller
    /// still gets.
    public func read(account: String, prompt: String, authentication: OwnerAuthentication?) throws -> VaultSecret {
        let context: LAContext
        if let carried = authentication?.keychainContext(for: account) {
            // The human already authenticated for this item, in a prompt that
            // named the destination and the label. `SecItemCopyMatching`
            // consults that evaluation rather than asking again.
            context = carried
        } else {
            context = LAContext()
            // Explicit, not defaulted. A read that is meant to raise its own
            // prompt must not be silently satisfied by an unrelated Touch ID
            // the owner performed seconds ago somewhere else in the app.
            context.touchIDAuthenticationAllowableReuseDuration = 0
        }
        context.localizedReason = prompt
        var query = KeychainAccessGroup.readAttributes(service: service, account: account, accessGroup: try accessGroup())
        query[kSecUseAuthenticationContext as String] = context
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            if status == errSecAuthFailed || status == errSecUserCanceled {
                throw VaultageError.approvalDenied
            }
            // Audit M-22: "no such record" is typed, so a caller that would
            // create one on its absence cannot create one beside an existing
            // record it merely failed to read.
            if status == errSecItemNotFound { throw VaultageError.destinationNotFound }
            throw VaultageError.storage("Protected vault item is unavailable (\(status)).")
        }
        // The Keychain hands back a Foundation `Data` whose buffer Vaultage does
        // not own and cannot zero. `VaultSecret` immediately copies it into an
        // allocation it does own; the residual copy is documented in
        // IMPLEMENTATION.md, "Secret material in memory".
        return VaultSecret(data)
    }

    public func delete(account: String) throws {
        let query = KeychainAccessGroup.deleteAttributes(service: service, account: account, accessGroup: try accessGroup())
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw VaultageError.storage("Could not delete protected vault item (\(status)).")
        }
    }
}
